// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

// certForKey builds a DER-encoded self-signed certificate from the
// supplied template + key. Used by saml_test.go to round-trip a signed XML
// document; in production saml.go uses the same primitives via
// x509.CreateCertificate.
func certForKey(template *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
}

// pemEncodeCert wraps a DER-encoded cert in the standard "CERTIFICATE"
// PEM envelope for the signing path's KeyInfo block.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// hmacHexImpl is the canonical "HMAC-SHA256 → hex" the dispatcher uses,
// re-exposed for tests so they don't reach into private helpers in
// production code.
func hmacHexImpl(secret, message string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}
