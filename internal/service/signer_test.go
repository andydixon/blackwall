// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestLocalDBSigner_RoundTrip confirms the Signer interface contract for the
// local-key backend: same key signs and verifies; a tampered payload fails.
func TestLocalDBSigner_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	s := NewLocalDBSigner("test-kid", key)

	if s.KeyID() != "test-kid" {
		t.Fatalf("KeyID mismatch: %s", s.KeyID())
	}
	if s.Algorithm() != "RS256" {
		t.Fatalf("Algorithm should be RS256, got %s", s.Algorithm())
	}
	if s.PublicKey() == nil {
		t.Fatalf("PublicKey nil")
	}

	body := []byte("blackwall.test.payload.v1")
	sig, err := s.Sign(body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}
	if err := s.Verify(body, sig); err != nil {
		t.Fatalf("Verify(valid): %v", err)
	}
	if err := s.Verify([]byte("blackwall.test.payload.v2"), sig); err == nil {
		t.Fatalf("Verify accepted tampered body")
	}
}

// TestKMSSignerStubFails confirms the placeholder backend refuses to sign
// rather than silently falling back. A misconfigured deployment should crash
// loudly at first token mint instead of looking like it's working.
func TestKMSSignerStubFails(t *testing.T) {
	s := &kmsSignerStub{backend: "aws_kms"}
	if _, err := s.Sign([]byte("anything")); err == nil {
		t.Fatalf("KMS stub Sign should error")
	}
	if err := s.Verify([]byte("anything"), []byte("sig")); err == nil {
		t.Fatalf("KMS stub Verify should error")
	}
}
