// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCryptbinVerifyKeyRejectsUntrustedArgon2Parameters(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verifier, err := CryptbinCreateVerifier(key)
	if err != nil {
		t.Fatalf("CryptbinCreateVerifier: %v", err)
	}
	if !CryptbinVerifyKey(key, verifier) {
		t.Fatal("valid verifier was rejected")
	}

	oversized := strings.Replace(verifier, "m=65536", "m=1048576", 1)
	if CryptbinVerifyKey(key, oversized) {
		t.Fatal("verifier with untrusted memory cost was accepted")
	}

	wrongVersion := strings.Replace(verifier, "v=19", "v=20", 1)
	if CryptbinVerifyKey(key, wrongVersion) {
		t.Fatal("verifier with unsupported version was accepted")
	}
}
