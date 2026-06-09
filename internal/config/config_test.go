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
