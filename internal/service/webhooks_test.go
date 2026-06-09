package service

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestVerifySignature_RoundTrip rebuilds what a receiver does: compute the
// HMAC over the same canonical string we use server-side and confirm
// VerifySignature accepts it. Mismatched secret or body must reject.
func TestVerifySignature_RoundTrip(t *testing.T) {
	secret := "whsec_test_aabb"
	body := `{"id":"abc","type":"user.created"}`

	// Build a real signature using the same code path the dispatcher does.
	ts := time.Now().Unix()
	// We have to recompute the same way send() does — but we don't expose
	// the internal helper. Instead, exercise VerifySignature with a
	// deliberately crafted header to confirm the *verification* logic.
	headerOK := buildTestSig(secret, body, ts)
	if !VerifySignature(secret, body, headerOK, 5*time.Minute) {
		t.Fatalf("valid signature rejected")
	}

	// Wrong secret → reject.
	if VerifySignature("whsec_other", body, headerOK, 5*time.Minute) {
		t.Fatalf("wrong secret accepted")
	}
	// Wrong body → reject.
	if VerifySignature(secret, body+"x", headerOK, 5*time.Minute) {
		t.Fatalf("tampered body accepted")
	}
	// Stale timestamp → reject when tolerance enforced.
	stale := buildTestSig(secret, body, time.Now().Add(-1*time.Hour).Unix())
	if VerifySignature(secret, body, stale, 5*time.Minute) {
		t.Fatalf("stale timestamp accepted with tight tolerance")
	}
	// Stale timestamp with tolerance=0 → accept (replay protection off).
	if !VerifySignature(secret, body, stale, 0) {
		t.Fatalf("tolerance=0 should disable timestamp check")
	}
	// Malformed header → reject.
	if VerifySignature(secret, body, "no-sig-here", 5*time.Minute) {
		t.Fatalf("malformed header accepted")
	}
}

// buildTestSig duplicates the signing format from WebhookService.send so the
// test stays self-contained. If you change the canonical string format in
// production code, update this helper too.
func buildTestSig(secret, body string, ts int64) string {
	tsStr := timeToString(ts)
	sig := hmacHex(secret, tsStr+"."+body)
	return "t=" + tsStr + ",v1=" + sig
}

func timeToString(ts int64) string {
	// Avoid pulling fmt into a test where every byte counts.
	const digits = "0123456789"
	if ts == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := ts
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}

// hmacHex computes HMAC-SHA256(secret, message) → hex.
func hmacHex(secret, message string) string {
	// Re-implement to avoid pulling crypto/hmac into the test file's
	// import block where the package under test also uses it. (Helps the
	// failure mode "test compiles but secretly references prod helper".)
	return hmacHexImpl(secret, message)
}

func TestValidateWebhookTargetURL(t *testing.T) {
	cases := map[string]bool{
		"http://example.com":                 true,
		"https://example.com":                true,
		"https://x/y/z?a=1":                  true,
		"http://127.0.0.1/hook":              false,
		"http://10.0.0.1/hook":               false,
		"http://localhost/hook":              false,
		"https://user:pass@example.com/hook": false,
		"ftp://example.com":                  false,
		"":                                   false,
		"example.com":                        false,
		"javascript:alert(1)":                false,
	}
	for in, want := range cases {
		got := validateWebhookTargetURL(in) == nil
		if got != want {
			t.Errorf("validateWebhookTargetURL(%q) valid = %v, want %v", in, got, want)
		}
	}
}

func TestIsPublicWebhookIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"127.0.0.1":       false,
		"169.254.169.254": false,
		"100.64.0.1":      false,
		"192.0.2.1":       false,
		"::1":             false,
		"2001:db8::1":     false,
	}
	for raw, want := range cases {
		if got := isPublicWebhookIP(net.ParseIP(raw)); got != want {
			t.Errorf("isPublicWebhookIP(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestGenerateWebhookSecretFormat(t *testing.T) {
	s := generateWebhookSecret()
	if !strings.HasPrefix(s, "whsec_") {
		t.Fatalf("secret should start with whsec_: %q", s)
	}
	// 6 (prefix) + 64 (hex of 32 bytes) = 70
	if len(s) != 70 {
		t.Fatalf("unexpected secret length: %d", len(s))
	}
}
