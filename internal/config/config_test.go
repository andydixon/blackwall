// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package config

import (
	"strings"
	"testing"
)

func TestValidateRejectsBodyLimitBelowCryptbinEnvelope(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = strings.Repeat("a", 32)
	cfg.CSRFSecret = strings.Repeat("b", 32)
	cfg.RequestBodyMaxBytes = 1024
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "request_body_max_bytes") {
		t.Fatalf("Validate() error = %v, want request body limit error", err)
	}
}

func TestValidateRequiresSecureAppURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = strings.Repeat("a", 32)
	cfg.CSRFSecret = strings.Repeat("b", 32)
	cfg.AppURL = "http://auth.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Validate() error = %v, want HTTPS error", err)
	}

	cfg.AppEnv = "development"
	cfg.AppURL = "http://localhost:8080/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback development URL rejected: %v", err)
	}
	if cfg.AppURL != "http://localhost:8080" {
		t.Fatalf("AppURL = %q, want trailing slash removed", cfg.AppURL)
	}
}

func TestValidateReminderSMTPRequiresEncryptedCompleteConfiguration(t *testing.T) {
	valid := defaults()
	valid.SessionSecret = strings.Repeat("a", 32)
	valid.CSRFSecret = strings.Repeat("b", 32)
	valid.LicenceRemindersEnabled = true
	valid.SMTPHost = "smtp.example.com"
	valid.SMTPPort = 587
	valid.SMTPUsername = "blackwall"
	valid.SMTPPassword = "deployment-secret"
	valid.SMTPFromAddress = "licences@example.com"
	valid.SMTPTLSMode = "starttls"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid reminder SMTP rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing host", func(c *Config) { c.SMTPHost = "" }},
		{"invalid host", func(c *Config) { c.SMTPHost = "-smtp.example.com" }},
		{"header injection", func(c *Config) { c.SMTPFromName = "Blackwall\r\nBcc: x@example.com" }},
		{"plaintext mode", func(c *Config) { c.SMTPTLSMode = "none" }},
		{"missing password", func(c *Config) { c.SMTPPassword = "" }},
		{"display-name from address", func(c *Config) { c.SMTPFromAddress = "Blackwall <licences@example.com>" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *valid
			tc.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid SMTP reminder configuration was accepted")
			}
		})
	}
}

func TestValidateWebAuthnExtraOrigins(t *testing.T) {
	base := func() *Config {
		cfg := defaults()
		cfg.SessionSecret = strings.Repeat("a", 32)
		cfg.CSRFSecret = strings.Repeat("b", 32)
		cfg.AppURL = "https://blackwall.cx"
		cfg.WebAuthnRPID = "blackwall.cx"
		return cfg
	}

	t.Run("accepts and normalises a subdomain", func(t *testing.T) {
		cfg := base()
		cfg.WebAuthnExtraOrigins = " https://admin.blackwall.cx/ , https://ops.blackwall.cx "
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
		if cfg.WebAuthnExtraOrigins != "https://admin.blackwall.cx,https://ops.blackwall.cx" {
			t.Fatalf("WebAuthnExtraOrigins = %q, want trimmed scheme+host list", cfg.WebAuthnExtraOrigins)
		}
	})

	t.Run("accepts the RP ID itself", func(t *testing.T) {
		cfg := base()
		cfg.WebAuthnExtraOrigins = "https://blackwall.cx"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	// Each of these would let an origin that can never legitimately hold a
	// credential for this RP ID past the ceremony's origin check.
	cases := []struct {
		name  string
		value string
	}{
		{"outside the RP ID", "https://blackwall.cx.evil.example"},
		{"suffix without dot boundary", "https://notblackwall.cx"},
		{"plaintext scheme", "http://admin.blackwall.cx"},
		{"carries a path", "https://admin.blackwall.cx/admin"},
		{"carries credentials", "https://user:pw@admin.blackwall.cx"},
		{"not a URL", "admin.blackwall.cx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.WebAuthnExtraOrigins = tc.value
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() accepted %q", tc.value)
			}
		})
	}
}
