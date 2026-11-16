// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"blackwall/internal/config"
)

type JWTManager struct {
	db     *sql.DB
	issuer string
}

func NewJWTManager(db *sql.DB) *JWTManager {
	cfg := config.Get()
	m := &JWTManager{db: db, issuer: cfg.AppURL}
	if err := m.ensureSigningKey(); err != nil {
		panic("jwt: failed to ensure signing key: " + err.Error())
	}
	return m
}

type signingKey struct {
	kid        string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (m *JWTManager) ensureSigningKey() error {
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM jwt_signing_keys WHERE is_active = 1`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return m.generateSigningKey()
	}
	return nil
}

func (m *JWTManager) generateSigningKey() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: func() []byte {
		b, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		return b
	}()})

	kid := make([]byte, 16)
	if _, err := rand.Read(kid); err != nil {
		return err
	}
	kidHex := fmt.Sprintf("%x", kid)

	_, err = m.db.Exec(`INSERT INTO jwt_signing_keys (kid, private_key, public_key, algorithm, is_active) VALUES (?, ?, ?, 'RS256', 1)`,
		kidHex, string(privPEM), string(pubPEM))
	return err
}

func (m *JWTManager) getActiveKey() (*signingKey, string, error) {
	var kid, privPEM, pubPEM string
	err := m.db.QueryRow(`SELECT kid, private_key, public_key FROM jwt_signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1`).
		Scan(&kid, &privPEM, &pubPEM)
	if err != nil {
		return nil, "", fmt.Errorf("no active JWT signing key: %w", err)
	}

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode private key PEM")
	}
	priv, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	return &signingKey{kid: kid, privateKey: priv, publicKey: &priv.PublicKey}, kid, nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return priv, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return priv, nil
}

func (m *JWTManager) CreateAccessToken(sub, aud, scope, projectUUID string, privilegeLevel int, privilegeName string, expiresIn int, nonce string) (string, error) {
	key, kid, err := m.getActiveKey()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":             m.issuer,
		"sub":             sub,
		"aud":             jwt.ClaimStrings{aud},
		"iat":             now.Unix(),
		"nbf":             now.Unix(),
		"exp":             now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"scope":           scope,
		"project_id":      projectUUID,
		"privilege_level": privilegeLevel,
		"privilege_name":  privilegeName,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key.privateKey)
}

// CreateIDToken signs an OIDC ID token. accessToken is optional; when supplied
// the at_hash claim is included per OIDC Core §3.1.3.6, computed as the
// base64url of the leftmost half of the SHA-256 of the access token's ASCII
// bytes. (For RS256 we always use SHA-256 regardless of access token format.)
//
// extraClaims is a custom-claim map merged AFTER all standard fields; we
// refuse to overwrite any standard / reserved claim regardless of what the
// caller passes, so a stored "iss" or "sub" custom claim cannot tamper with
// token security semantics.
func (m *JWTManager) CreateIDToken(sub, aud, nonce, email, name, accessToken string, authTime int64, extraClaims map[string]interface{}) (string, error) {
	key, kid, err := m.getActiveKey()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": m.issuer,
		"sub": sub,
		"aud": jwt.ClaimStrings{aud},
		"iat": now.Unix(),
		"exp": now.Add(3600 * time.Second).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if email != "" {
		claims["email"] = email
	}
	if name != "" {
		claims["name"] = name
	}
	if authTime > 0 {
		claims["auth_time"] = authTime
	}
	if accessToken != "" {
		claims["at_hash"] = computeAtHash(accessToken)
	}

	// Merge custom claims last; the protectedClaims set blocks overrides of
	// any standard claim (extra defence in depth — the OIDCClaimsService
	// already rejects reserved keys at write time).
	for k, v := range extraClaims {
		if _, locked := protectedClaims[k]; locked {
			continue
		}
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key.privateKey)
}

// protectedClaims is the union of every claim the issuer controls. A custom
// claim with the same name is dropped silently rather than overriding the
// signed-by-us value.
var protectedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "iat": {}, "exp": {}, "nbf": {},
	"jti": {}, "nonce": {}, "at_hash": {}, "c_hash": {},
	"auth_time": {}, "acr": {}, "amr": {}, "azp": {},
}

// computeAtHash returns the base64url-encoded leftmost half of SHA-256(at).
// Per OIDC Core §3.1.3.6 with alg=RS256: take SHA-256 of the access token's
// ASCII bytes, keep the first 128 bits, base64url-encode without padding.
func computeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// activeSigner returns the JWT manager's active key wrapped in a Signer.
// This is the single seam through which non-token signing operations (e.g.
// AuditChainService checkpoints) reach the platform's signing key without
// reaching back into the db row directly.
func (m *JWTManager) activeSigner() (Signer, error) {
	key, kid, err := m.getActiveKey()
	if err != nil {
		return nil, err
	}
	return NewLocalDBSigner(kid, key.privateKey), nil
}

// SignBytes produces a detached PKCS#1 v1.5 RSA-SHA256 signature over data
// using the active JWT key. Returns the kid alongside the signature so a
// later verifier knows which key to consult after rotation.
func (m *JWTManager) SignBytes(data []byte) (kid string, sig []byte, err error) {
	signer, err := m.activeSigner()
	if err != nil {
		return "", nil, err
	}
	out, err := signer.Sign(data)
	if err != nil {
		return "", nil, err
	}
	return signer.KeyID(), out, nil
}

// VerifyBytes checks a detached signature produced by SignBytes against any
// known (active or retired) JWT signing key. Useful for replaying historical
// signatures after a key rotation — the key that signed is identified by the
// stored signing_key_id on the relevant record.
func (m *JWTManager) VerifyBytes(data, sig []byte) bool {
	rows, err := m.db.Query(`SELECT public_key FROM jwt_signing_keys`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var pubPEM string
		if err := rows.Scan(&pubPEM); err != nil {
			continue
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			continue
		}
		sum := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sum[:], sig); err == nil {
			return true
		}
	}
	return false
}

type ParsedToken struct {
	Claims jwt.MapClaims
	Valid  bool
}

func (m *JWTManager) ParseAndValidate(tokenStr string) (*ParsedToken, error) {
	// Collect active public keys
	rows, err := m.db.Query(`SELECT kid, public_key FROM jwt_signing_keys WHERE is_active = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := map[string]*rsa.PublicKey{}
	for rows.Next() {
		var kid, pubPEM string
		if err := rows.Scan(&kid, &pubPEM); err != nil {
			continue
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			keys[kid] = rsaPub
		}
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		// Try all keys if kid not found
		for _, k := range keys {
			return k, nil
		}
		return nil, fmt.Errorf("no matching key")
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired())

	if err != nil || !token.Valid {
		return &ParsedToken{Valid: false}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &ParsedToken{Valid: false}, nil
	}

	return &ParsedToken{Claims: claims, Valid: true}, nil
}

func (m *JWTManager) GetJWKS() map[string]interface{} {
	rows, err := m.db.Query(`SELECT kid, public_key, algorithm FROM jwt_signing_keys WHERE is_active = 1`)
	if err != nil {
		return map[string]interface{}{"keys": []interface{}{}}
	}
	defer rows.Close()

	var keys []map[string]interface{}
	for rows.Next() {
		var kid, pubPEM, alg string
		if err := rows.Scan(&kid, &pubPEM, &alg); err != nil {
			continue
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			continue
		}
		nBytes := rsaPub.N.Bytes()
		eBytes := big.NewInt(int64(rsaPub.E)).Bytes()
		keys = append(keys, map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"alg": alg,
			"kid": kid,
			"n":   strings.TrimRight(base64.URLEncoding.EncodeToString(nBytes), "="),
			"e":   strings.TrimRight(base64.URLEncoding.EncodeToString(eBytes), "="),
		})
	}
	if keys == nil {
		keys = []map[string]interface{}{}
	}
	return map[string]interface{}{"keys": keys}
}
