// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"testing"

	"blackwall/internal/config"
)

// The origin check is the only thing standing between a credential scoped to
// the RP ID and a ceremony driven from some other page under it, so pin both
// directions: extras are honoured, and nothing else slips through.
func TestWebAuthnOriginAllowed(t *testing.T) {
	original := config.Get()
	t.Cleanup(func() { config.Set(original) })

	cfg := &config.Config{}
	cfg.AppURL = "https://blackwall.cx"
	cfg.WebAuthnRPID = "blackwall.cx"
	cfg.WebAuthnExtraOrigins = "https://admin.blackwall.cx"
	config.Set(cfg)

	svc := &WebAuthnService{rpID: cfg.WebAuthnRPID}

	cases := []struct {
		origin string
		want   bool
	}{
		{"https://blackwall.cx", true},
		{"https://admin.blackwall.cx", true},
		{"https://other.blackwall.cx", false},
		{"http://admin.blackwall.cx", false},
		{"https://admin.blackwall.cx:8443", false},
		{"https://blackwall.cx.evil.example", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := svc.originAllowed(tc.origin); got != tc.want {
			t.Errorf("originAllowed(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}

// With no extras configured the check must stay exactly as strict as it was
// before the allow-list existed.
func TestWebAuthnOriginAllowedWithoutExtras(t *testing.T) {
	original := config.Get()
	t.Cleanup(func() { config.Set(original) })

	cfg := &config.Config{}
	cfg.AppURL = "https://blackwall.cx"
	cfg.WebAuthnRPID = "blackwall.cx"
	config.Set(cfg)

	svc := &WebAuthnService{rpID: cfg.WebAuthnRPID}

	if !svc.originAllowed("https://blackwall.cx") {
		t.Error("app_url origin rejected")
	}
	if svc.originAllowed("https://admin.blackwall.cx") {
		t.Error("subdomain accepted without being configured")
	}
}
