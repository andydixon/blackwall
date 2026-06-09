package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"blackwall/internal/config"
	"blackwall/internal/security"
)

func TestPopSessionStringConsumesSecret(t *testing.T) {
	cfg := &config.Config{
		AppURL:          "https://test.example",
		SessionName:     "test_session",
		SessionSecret:   strings.Repeat("a", 32),
		CSRFSecret:      strings.Repeat("b", 32),
		SessionLifetime: 3600,
	}
	config.Set(cfg)
	security.InitSession(cfg)

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "https://test.example/", nil)
	s1, _ := security.GetSession(w1, r1)
	s1.Set(flashAdminTokenPlaintext, "bw_admin_secret")
	if err := s1.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}

	r2 := httptest.NewRequest("GET", "https://test.example/", nil)
	r2.AddCookie(w1.Result().Cookies()[0])
	w2 := httptest.NewRecorder()
	s2, _ := security.GetSession(w2, r2)
	if got := popSessionString(s2, flashAdminTokenPlaintext); got != "bw_admin_secret" {
		t.Fatalf("pop = %q", got)
	}
	if err := s2.Save(); err != nil {
		t.Fatalf("save consumed session: %v", err)
	}

	r3 := httptest.NewRequest("GET", "https://test.example/", nil)
	r3.AddCookie(w2.Result().Cookies()[0])
	w3 := httptest.NewRecorder()
	s3, _ := security.GetSession(w3, r3)
	if got := popSessionString(s3, flashAdminTokenPlaintext); got != "" {
		t.Fatalf("secret remained after consumption: %q", got)
	}
}
