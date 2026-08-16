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
