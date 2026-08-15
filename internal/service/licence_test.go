package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLicenceClaims(publicKey ed25519.PublicKey) LicenceClaims {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	return LicenceClaims{
		Version:            1,
		LicenceID:          "38a46ec2-7f4d-4a77-99dc-2298b16acb08",
		Issuer:             "https://blackwall.cx",
		Audience:           licenceAudience,
		ProjectUUID:        "aa88643b-889d-4ce7-a96d-4a562065c880",
		Entity:             LicenceEntity{Type: "business", Name: "Example Limited", Reference: "CUS-42"},
		Hostnames:          []string{"app.example.com"},
		Features:           []string{"api", "reports"},
		MaxInstances:       2,
		IssuedAt:           now.Unix(),
		NotBefore:          now.Unix(),
		ExpiresAt:          now.Add(365 * 24 * time.Hour).Unix(),
		KeyID:              licenceKeyID(publicKey),
		StatusURL:          "https://blackwall.cx/licences/v1/verify",
		OnlineCheckSeconds: 86400,
	}
}

func TestLicenceSignatureRoundTripAndTamperRejection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := testLicenceClaims(publicKey)
	token, _, _, err := SignLicence(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, _, err := VerifyLicenceSignature(token, publicKey)
	if err != nil {
		t.Fatalf("valid licence rejected: %v", err)
	}
	if verified.LicenceID != claims.LicenceID {
		t.Fatalf("licence ID mismatch: %q", verified.LicenceID)
	}

	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload[len(payload)-2] ^= 1
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	if _, _, _, err := VerifyLicenceSignature(strings.Join(parts, "."), publicKey); err == nil {
		t.Fatal("tampered payload was accepted")
	}

	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, _, err := VerifyLicenceSignature(token, otherPublic); err == nil {
		t.Fatal("licence was accepted with the wrong key")
	}
}

func TestLicenceEnvelopeRejectsUnknownAndNonCanonicalClaims(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	claims := testLicenceClaims(publicKey)
	token, _, _, _ := SignLicence(privateKey, claims)
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), `{"v":1`, `{ "v":1`, 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	parts[2] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(parts[0]+"."+parts[1])))
	if _, _, _, err := VerifyLicenceSignature(strings.Join(parts, "."), publicKey); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("non-canonical signed JSON should be rejected, got: %v", err)
	}

	payload = []byte(strings.Replace(string(payload), `"v":1`, `"unexpected":true,"v":1`, 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	parts[2] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(parts[0]+"."+parts[1])))
	if _, _, _, err := VerifyLicenceSignature(strings.Join(parts, "."), publicKey); err == nil {
		t.Fatal("unknown claim should be rejected")
	}
}

func TestNormaliseLicenceHostnamesUsesExactCanonicalNames(t *testing.T) {
	got, err := NormaliseLicenceHostnames([]string{"API.Example.COM.", "app.example.com", "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "app.example.com"}
	if !stringSlicesEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for _, invalid := range []string{"*.example.com", "https://example.com", "example.com:443", "exa_mple.com", "éxample.com"} {
		if _, err := NormaliseLicenceHostname(invalid); err == nil {
			t.Errorf("invalid hostname %q was accepted", invalid)
		}
	}
}

func TestCheckLicenceClaimsBindsIssuerProjectHostnameAndTime(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	claims := testLicenceClaims(publicKey)
	now := time.Unix(claims.IssuedAt, 0)
	project := claims.ProjectUUID
	if code := CheckLicenceClaims(&claims, claims.Issuer, "APP.EXAMPLE.COM.", project, now, 2*time.Minute); code != "valid" {
		t.Fatalf("expected valid, got %q", code)
	}
	if code := CheckLicenceClaims(&claims, "https://attacker.example", "app.example.com", project, now, 0); code != "issuer_mismatch" {
		t.Fatalf("expected issuer mismatch, got %q", code)
	}
	if code := CheckLicenceClaims(&claims, claims.Issuer, "other.example.com", project, now, 0); code != "hostname_mismatch" {
		t.Fatalf("expected hostname mismatch, got %q", code)
	}
	if code := CheckLicenceClaims(&claims, claims.Issuer, "app.example.com", project, time.Unix(claims.ExpiresAt+1, 0), 0); code != "expired" {
		t.Fatalf("expected expiry, got %q", code)
	}
}

func TestLoadLicencePrivateKeyRequiresRestrictedPKCS8Ed25519File(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "licence.pem")
	contents := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLicencePrivateKey(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("world-readable key should be rejected, got: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLicencePrivateKey(path)
	if err != nil {
		t.Fatalf("restricted PKCS#8 key rejected: %v", err)
	}
	if !loaded.Equal(privateKey) {
		t.Fatal("loaded key does not match source key")
	}
}
