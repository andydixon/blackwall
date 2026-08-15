package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	faviconMaximumBytes = 128 * 1024
	faviconCacheEntries = 256
)

var errFaviconUnavailable = errors.New("favicon unavailable")

// FaviconService retrieves the conventional favicon for a registered OAuth
// redirect host. It deliberately does not parse arbitrary HTML or follow
// redirects: either would considerably enlarge the SSRF and content-handling
// surface for a cosmetic authentication-screen feature.
type FaviconService struct {
	mu       sync.Mutex
	cache    map[string]faviconCacheEntry
	inFlight map[string]*faviconFlight
	resolver *net.Resolver
	now      func() time.Time
}

type faviconCacheEntry struct {
	data        []byte
	contentType string
	expiresAt   time.Time
	lastUsedAt  time.Time
	available   bool
}

type faviconFlight struct {
	done chan struct{}
}

// NewFaviconService creates a bounded, in-memory cache. Icons are deliberately
// not persisted because they are untrusted presentation data from another
// service and can be refreshed safely after a restart.
func NewFaviconService() *FaviconService {
	return &FaviconService{
		cache:    make(map[string]faviconCacheEntry),
		inFlight: make(map[string]*faviconFlight),
		resolver: net.DefaultResolver,
		now:      time.Now,
	}
}

// Fetch returns a remotely supplied favicon only after the target and every
// resolved address have passed the SSRF policy. Concurrent requests for the
// same host share one fetch.
func (s *FaviconService) Fetch(ctx context.Context, redirectURI string) ([]byte, string, error) {
	host, err := faviconTargetHost(redirectURI)
	if err != nil {
		return nil, "", errFaviconUnavailable
	}

	for {
		now := s.now()
		s.mu.Lock()
		if cached, ok := s.cache[host]; ok && now.Before(cached.expiresAt) {
			cached.lastUsedAt = now
			s.cache[host] = cached
			s.mu.Unlock()
			if !cached.available {
				return nil, "", errFaviconUnavailable
			}
			return append([]byte(nil), cached.data...), cached.contentType, nil
		}
		if flight, ok := s.inFlight[host]; ok {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, "", errFaviconUnavailable
			case <-flight.done:
				continue
			}
		}
		flight := &faviconFlight{done: make(chan struct{})}
		s.inFlight[host] = flight
		s.mu.Unlock()

		data, contentType, fetchErr := s.fetch(ctx, host)
		now = s.now()
		if fetchErr != nil && ctx.Err() != nil {
			s.mu.Lock()
			delete(s.inFlight, host)
			close(flight.done)
			s.mu.Unlock()
			return nil, "", errFaviconUnavailable
		}
		entry := faviconCacheEntry{
			data:        append([]byte(nil), data...),
			contentType: contentType,
			lastUsedAt:  now,
			available:   fetchErr == nil,
		}
		if fetchErr == nil {
			entry.expiresAt = now.Add(24 * time.Hour)
		} else {
			// Negative caching prevents a missing icon from causing an outbound
			// request on every authentication page load.
			entry.expiresAt = now.Add(10 * time.Minute)
		}

		s.mu.Lock()
		s.evictOneIfNeeded()
		s.cache[host] = entry
		delete(s.inFlight, host)
		close(flight.done)
		s.mu.Unlock()

		if fetchErr != nil {
			return nil, "", errFaviconUnavailable
		}
		return append([]byte(nil), data...), contentType, nil
	}
}

func (s *FaviconService) fetch(ctx context.Context, host string) ([]byte, string, error) {
	resolveCtx, cancelResolve := context.WithTimeout(ctx, 2*time.Second)
	addresses, err := s.resolver.LookupIPAddr(resolveCtx, host)
	cancelResolve()
	if err != nil || len(addresses) == 0 {
		return nil, "", errFaviconUnavailable
	}

	pinned := make([]net.IP, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address.IP)
		if !ok || !isPublicFaviconAddress(parsed.Unmap()) {
			// Reject the whole hostname if DNS mixes public and non-public
			// answers. Selecting only the public result would make rebinding
			// behaviour depend on resolver ordering.
			return nil, "", errFaviconUnavailable
		}
		key := address.IP.String()
		if _, duplicate := seen[key]; !duplicate {
			seen[key] = struct{}{}
			pinned = append(pinned, append(net.IP(nil), address.IP...))
		}
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		},
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, address := range pinned {
				connection, dialErr := dialer.DialContext(dialCtx, network, net.JoinHostPort(address.String(), "443"))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/favicon.ico", nil)
	if err != nil {
		return nil, "", errFaviconUnavailable
	}
	request.Header.Set("Accept", "image/png,image/jpeg,image/gif,image/webp,image/x-icon,image/vnd.microsoft.icon")
	request.Header.Set("User-Agent", "Blackwall-Favicon/1.0")

	response, err := client.Do(request)
	if err != nil {
		return nil, "", errFaviconUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > faviconMaximumBytes {
		return nil, "", errFaviconUnavailable
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, faviconMaximumBytes+1))
	if err != nil || len(data) == 0 || len(data) > faviconMaximumBytes {
		return nil, "", errFaviconUnavailable
	}
	contentType := http.DetectContentType(data)
	if !allowedFaviconContentType(contentType) {
		return nil, "", errFaviconUnavailable
	}
	return data, contentType, nil
}

func (s *FaviconService) evictOneIfNeeded() {
	if len(s.cache) < faviconCacheEntries {
		return
	}
	var oldestHost string
	var oldestTime time.Time
	for host, entry := range s.cache {
		if oldestHost == "" || entry.lastUsedAt.Before(oldestTime) {
			oldestHost = host
			oldestTime = entry.lastUsedAt
		}
	}
	delete(s.cache, oldestHost)
}

func faviconTargetHost(rawURI string) (string, error) {
	if len(rawURI) == 0 || len(rawURI) > 2048 {
		return "", fmt.Errorf("redirect URI length is invalid")
	}
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil {
		return "", fmt.Errorf("redirect URI is not a plain HTTPS URL")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return "", fmt.Errorf("redirect URI uses a non-standard port")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return "", fmt.Errorf("redirect URI hostname is not eligible")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("redirect URI hostname is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("redirect URI hostname is not ASCII DNS")
			}
		}
	}
	return host, nil
}

func allowedFaviconContentType(contentType string) bool {
	switch contentType {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon":
		return true
	default:
		return false
	}
}

func isPublicFaviconAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range faviconBlockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var faviconBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}
