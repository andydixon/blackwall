package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"blackwall/internal/config"
	"blackwall/internal/service"
)

type contextKey string

const (
	CorrelationIDKey contextKey = "correlation_id"
	IPAddressKey     contextKey = "ip_address"
	AuditLoggerKey   contextKey = "audit_logger"
)

func CorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Correlation-Id")
		if id == "" || !isValidUUID(id) {
			id = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), CorrelationIDKey, id)
		w.Header().Set("X-Correlation-Id", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func IPAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ctx := context.WithValue(r.Context(), IPAddressKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractIP(r *http.Request) string {
	cfg := config.Get()
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if cfg.TrustProxy {
		trusted := parseTrustedProxies(cfg.TrustedProxies)
		// XFF/X-Real-IP headers are only honoured when the request actually
		// arrives from a configured trusted proxy. Otherwise any client could
		// spoof their apparent IP by setting the header themselves.
		if isTrustedProxy(remoteHost, trusted) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ips := splitAndValidateIPs(xff)
				// Walk the chain right-to-left and pick the first hop that is
				// not itself a trusted proxy — i.e. the real client.
				for i := len(ips) - 1; i >= 0; i-- {
					if !isTrustedProxy(ips[i], trusted) {
						return ips[i]
					}
				}
				if len(ips) > 0 {
					return ips[len(ips)-1]
				}
			}
			if xri := r.Header.Get("X-Real-IP"); xri != "" && net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	if net.ParseIP(remoteHost) != nil {
		return remoteHost
	}
	return "0.0.0.0"
}

func splitAndValidateIPs(header string) []string {
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if net.ParseIP(ip) != nil {
			out = append(out, ip)
		}
	}
	return out
}

func parseTrustedProxies(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

func isTrustedProxy(ip string, entries []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(parsed) {
				return true
			}
			continue
		}
		if entryIP := net.ParseIP(entry); entryIP != nil && entryIP.Equal(parsed) {
			return true
		}
	}
	return false
}

func AuditContext(_ interface{}, logger *service.AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			corrID, _ := r.Context().Value(CorrelationIDKey).(string)
			ip, _ := r.Context().Value(IPAddressKey).(string)
			ua := r.UserAgent()
			l := logger.WithContext(corrID, ip, ua)
			ctx := context.WithValue(r.Context(), AuditLoggerKey, l)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

		// /oauth/authorize must POST consent back to itself or redirect to a
		// client-supplied redirect_uri, so form-action is widened to https
		// schemes plus localhost loopbacks. All other paths only allow self.
		formAction := "form-action 'self'"
		if r.URL.Path == "/oauth/authorize" {
			formAction = "form-action 'self' https: http://localhost:* http://127.0.0.1:* http://[::1]:*"
		}

		csp := strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
			"img-src 'self' data:",
			"connect-src 'self'",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			formAction,
		}, "; ")
		h.Set("Content-Security-Policy", csp)

		// HSTS is only meaningful over HTTPS — emitting it over plain HTTP
		// would let an attacker poison the policy and lock real HTTPS clients
		// onto a stale max-age in dev/test environments.
		isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		if isHTTPS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// GetAuditLogger retrieves the audit logger from the request context.
func GetAuditLogger(r *http.Request) *service.AuditLogger {
	if l, ok := r.Context().Value(AuditLoggerKey).(*service.AuditLogger); ok {
		return l
	}
	return nil
}

// GetIP retrieves the client IP from the request context.
func GetIP(r *http.Request) string {
	if ip, ok := r.Context().Value(IPAddressKey).(string); ok {
		return ip
	}
	return ""
}

// GetCorrelationID retrieves the correlation ID from the request context.
func GetCorrelationID(r *http.Request) string {
	if id, ok := r.Context().Value(CorrelationIDKey).(string); ok {
		return id
	}
	return ""
}
