// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestFaviconTargetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
		host string
	}{
		{"registered HTTPS redirect", "https://portal.example.com/oauth/callback", "portal.example.com"},
		{"explicit standard port", "https://portal.example.com:443/callback", "portal.example.com"},
		{"punycode hostname", "https://xn--bcher-kva.example/callback", "xn--bcher-kva.example"},
		{"reject HTTP", "http://portal.example.com/callback", ""},
		{"reject user information", "https://user@portal.example.com/callback", ""},
		{"reject custom port", "https://portal.example.com:8443/callback", ""},
		{"reject IPv4 literal", "https://8.8.8.8/callback", ""},
		{"reject IPv6 literal", "https://[2001:4860:4860::8888]/callback", ""},
		{"reject trailing dot", "https://portal.example.com./callback", ""},
		{"reject malformed label", "https://-portal.example.com/callback", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host, err := faviconTargetHost(test.uri)
			if test.host == "" {
				if err == nil {
					t.Fatalf("faviconTargetHost(%q) unexpectedly returned %q", test.uri, host)
				}
				return
			}
			if err != nil || host != test.host {
				t.Fatalf("faviconTargetHost(%q) = %q, %v; want %q", test.uri, host, err, test.host)
			}
		})
	}
}

func TestIsPublicFaviconAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		address string
		public  bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"169.254.169.254", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"2002:0808:0808::1", false},
	}

	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			t.Parallel()
			got := isPublicFaviconAddress(netip.MustParseAddr(test.address))
			if got != test.public {
				t.Fatalf("isPublicFaviconAddress(%s) = %t; want %t", test.address, got, test.public)
			}
		})
	}
}

func TestAllowedFaviconContentType(t *testing.T) {
	t.Parallel()

	for _, contentType := range []string{"image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon"} {
		if !allowedFaviconContentType(contentType) {
			t.Errorf("expected %s to be allowed", contentType)
		}
	}
	for _, contentType := range []string{"image/svg+xml", "text/html; charset=utf-8", "application/octet-stream"} {
		if allowedFaviconContentType(contentType) {
			t.Errorf("expected %s to be rejected", contentType)
		}
	}

	if got := http.DetectContentType([]byte("<svg xmlns='http://www.w3.org/2000/svg'></svg>")); allowedFaviconContentType(got) {
		t.Fatalf("SVG sniffed as %q must remain rejected", got)
	}
}
