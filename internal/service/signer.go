// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// Signer abstracts the private-key operations the JWT manager needs so a
// future deployment can keep key material in an external KMS / HSM instead
// of the local jwt_signing_keys table. The interface is intentionally narrow
// — only Sign + Verify + Algorithm + the public key for JWKS export —
// because RS256 token signing only needs those primitives.
//
// Backends we intend to support (in order of likely demand):
//   - LocalDBSigner: the existing path; private key sits in the DB and is
//     loaded into the process at boot. Backwards-compatible, zero-config.
//   - AWSKMSSigner: KMS asymmetric KeySpec=RSA_2048 with KeyUsage=SIGN_VERIFY.
//     Private key never leaves AWS; we send a SHA-256 digest, KMS returns
//     the signature.
//   - GCPKMSSigner: cloudkms asymmetric RSA_SIGN_PKCS1_2048_SHA256.
//   - VaultSigner: HashiCorp Vault Transit engine.
//
// All backends produce RFC 8017 PKCS#1 v1.5 RSA-SHA256 signatures so the
// public-facing /oauth/jwks document, ID tokens, and access tokens are
// indistinguishable from the local-key path regardless of backend.
type Signer interface {
	// KeyID returns the JWKS `kid` to embed in token headers.
	KeyID() string
	// Algorithm returns the JOSE `alg` for the produced signatures.
	Algorithm() string
	// PublicKey returns the RSA public key for JWKS export and verification.
	PublicKey() *rsa.PublicKey
	// Sign produces an RS256 signature over the supplied bytes.
	Sign(data []byte) ([]byte, error)
	// Verify checks an RS256 signature against the supplied bytes. We expose
	// this on the signer interface (rather than only via PublicKey()) so an
	// HSM / KMS backend can verify entirely server-side without ever
	// returning the public key to the caller, which some compliance regimes
	// prefer.
	Verify(data, sig []byte) error
}

// LocalDBSigner is the historic path: private key materialised into the
// process from the jwt_signing_keys table. We wrap a *rsa.PrivateKey rather
// than reaching back into the DB on every signature, so signing is a pure
// in-memory operation. KeyID and PublicKey are derived from the same row.
type LocalDBSigner struct {
	kid string
	key *rsa.PrivateKey
}

func NewLocalDBSigner(kid string, key *rsa.PrivateKey) *LocalDBSigner {
	return &LocalDBSigner{kid: kid, key: key}
}

func (s *LocalDBSigner) KeyID() string           { return s.kid }
func (s *LocalDBSigner) Algorithm() string       { return "RS256" }
func (s *LocalDBSigner) PublicKey() *rsa.PublicKey { return &s.key.PublicKey }

func (s *LocalDBSigner) Sign(data []byte) ([]byte, error) {
	if s.key == nil {
		return nil, errors.New("signer: no private key loaded")
	}
	sum := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
}

func (s *LocalDBSigner) Verify(data, sig []byte) error {
	if s.key == nil {
		return errors.New("signer: no key loaded")
	}
	sum := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig)
}

// kmsSignerStub is the placeholder backend wired in via the `signer_backend`
// config knob when an operator picks `aws_kms`, `gcp_kms`, or `vault` but the
// real integration hasn't been linked into the binary yet. It refuses to
// sign so a misconfigured deployment fails loudly at the first token mint
// rather than silently falling back to local keys.
//
// The real backends live in their own files (signer_aws.go, signer_gcp.go,
// signer_vault.go) behind build tags so cloud SDKs only bloat the binary
// when actually requested.
type kmsSignerStub struct{ backend string }

func (s *kmsSignerStub) KeyID() string             { return "kms-stub-" + s.backend }
func (s *kmsSignerStub) Algorithm() string         { return "RS256" }
func (s *kmsSignerStub) PublicKey() *rsa.PublicKey { return nil }
func (s *kmsSignerStub) Sign(_ []byte) ([]byte, error) {
	return nil, errors.New("KMS signer backend '" + s.backend + "' not compiled into this binary; rebuild with the matching build tag")
}
func (s *kmsSignerStub) Verify(_, _ []byte) error {
	return errors.New("KMS signer backend '" + s.backend + "' not compiled into this binary")
}
