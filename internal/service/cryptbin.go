// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"blackwall/internal/config"
)

const (
	base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	idLength    = 16
)

// PHP storage matches /^[0-9A-Za-z]{16}$/
var validIDRegex = regexp.MustCompile(`^[0-9A-Za-z]{16}$`)

// PHP sanitize regex: /[^A-Za-z0-9._-]/
var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// CryptbinMeta mirrors the PHP metadata JSON layout exactly so files written
// by either implementation can be read by the other.
type CryptbinMeta struct {
	ID                         string `json:"id,omitempty"`
	Version                    int    `json:"version,omitempty"`
	ItemType                   string `json:"item_type"`
	OriginalFilename           string `json:"original_filename,omitempty"`
	MimeType                   string `json:"mime_type,omitempty"`
	CipherAlg                  string `json:"cipher_alg,omitempty"`
	CipherNonceB64URL          string `json:"cipher_nonce_b64url,omitempty"`
	WrappedDEK                 string `json:"wrapped_dek,omitempty"`
	WrappedDEKNonce            string `json:"wrapped_dek_nonce,omitempty"`
	WrappedDEKAlg              string `json:"wrapped_dek_alg,omitempty"`
	KEKVersion                 string `json:"kek_version,omitempty"`
	Verifier                   string `json:"verifier,omitempty"`
	CreatedAt                  string `json:"created_at,omitempty"`
	UpdatedAt                  string `json:"updated_at,omitempty"`
	ExpiresAt                  string `json:"expires_at,omitempty"`
	RequiresWebAuthnForView    bool   `json:"requires_webauthn_for_view,omitempty"`
	WebAuthnCredentialID       int    `json:"webauthn_credential_id,omitempty"`
	WebAuthnCredentialPublicID string `json:"webauthn_credential_public_id,omitempty"`
	SizeBytes                  int64  `json:"size_bytes,omitempty"`
}

type CryptbinStorage struct {
	basePath string
}

func NewCryptbinStorage() *CryptbinStorage {
	cfg := config.Get()
	path := strings.TrimRight(cfg.CryptbinStoragePath, "/")
	if path == "" {
		path = "/var/lib/blackwall/cryptbin"
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		log.Printf("warn: cryptbin storage init failed: path=%q err=%v", path, err)
	}
	return &CryptbinStorage{basePath: path}
}

func (s *CryptbinStorage) BasePath() string {
	return s.basePath
}

func (s *CryptbinStorage) GenerateID() (string, error) {
	id := make([]byte, idLength)
	for i := range id {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(base62Chars))))
		if err != nil {
			return "", err
		}
		id[i] = base62Chars[n.Int64()]
	}
	return string(id), nil
}

func (s *CryptbinStorage) ValidateID(id string) bool {
	return validIDRegex.MatchString(id)
}

func (s *CryptbinStorage) binPath(id string) string {
	return filepath.Join(s.basePath, id+".bin")
}

func (s *CryptbinStorage) metaPath(id string) string {
	return filepath.Join(s.basePath, id+".json")
}

func (s *CryptbinStorage) Exists(id string) bool {
	if !s.ValidateID(id) {
		return false
	}
	if _, err := os.Stat(s.binPath(id)); err != nil {
		return false
	}
	if _, err := os.Stat(s.metaPath(id)); err != nil {
		return false
	}
	return true
}

func (s *CryptbinStorage) ReadMeta(id string) (*CryptbinMeta, error) {
	if !s.ValidateID(id) {
		return nil, errors.New("invalid id")
	}
	data, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var meta CryptbinMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (s *CryptbinStorage) ReadCiphertext(id string) ([]byte, error) {
	if !s.ValidateID(id) {
		return nil, errors.New("invalid id")
	}
	return os.ReadFile(s.binPath(id))
}

func (s *CryptbinStorage) WriteItem(id string, meta *CryptbinMeta, ciphertext []byte) error {
	if !s.ValidateID(id) {
		return errors.New("invalid id")
	}
	meta.ID = id
	meta.SizeBytes = int64(len(ciphertext))

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	tmpBin, err := s.tempPath(id, "bin")
	if err != nil {
		return err
	}
	tmpMeta, err := s.tempPath(id, "json")
	if err != nil {
		return err
	}
	defer os.Remove(tmpBin)
	defer os.Remove(tmpMeta)

	if err := writeAtomic(tmpBin, ciphertext, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(tmpMeta, metaJSON, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpBin, s.binPath(id)); err != nil {
		return err
	}
	return os.Rename(tmpMeta, s.metaPath(id))
}

func (s *CryptbinStorage) UpdateMeta(id string, meta *CryptbinMeta) error {
	if !s.ValidateID(id) {
		return errors.New("invalid id")
	}
	meta.ID = id
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmpMeta, err := s.tempPath(id, "json")
	if err != nil {
		return err
	}
	defer os.Remove(tmpMeta)
	if err := writeAtomic(tmpMeta, metaJSON, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpMeta, s.metaPath(id))
}

func (s *CryptbinStorage) DeleteItem(id string) error {
	if !s.ValidateID(id) {
		return errors.New("invalid id")
	}
	binErr := os.Remove(s.binPath(id))
	metaErr := os.Remove(s.metaPath(id))
	if binErr != nil && !os.IsNotExist(binErr) {
		return binErr
	}
	if metaErr != nil && !os.IsNotExist(metaErr) {
		return metaErr
	}
	return nil
}

func (s *CryptbinStorage) ListAll() ([]string, error) {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if s.ValidateID(id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *CryptbinStorage) SanitizeFilename(name, itemType string) string {
	if itemType == "text" {
		return "cryptbin.txt"
	}
	base := strings.TrimSpace(name)
	if base == "" {
		return "cryptbin.bin"
	}
	base = filepath.Base(base)
	base = unsafeFilenameChars.ReplaceAllString(base, "_")
	if base == "" || base == "." || base == ".." {
		return "cryptbin.bin"
	}
	return base
}

// PublicMeta returns the metadata fields safe to expose to a viewing client
// (everything except the verifier and wrapped-DEK material).
func (s *CryptbinStorage) PublicMeta(m *CryptbinMeta) map[string]interface{} {
	out := map[string]interface{}{
		"id":                         m.ID,
		"version":                    m.Version,
		"item_type":                  m.ItemType,
		"cipher_alg":                 m.CipherAlg,
		"cipher_nonce_b64url":        m.CipherNonceB64URL,
		"created_at":                 m.CreatedAt,
		"updated_at":                 m.UpdatedAt,
		"requires_webauthn_for_view": m.RequiresWebAuthnForView,
		"size_bytes":                 m.SizeBytes,
	}
	if m.OriginalFilename != "" {
		out["original_filename"] = m.OriginalFilename
	}
	if m.MimeType != "" {
		out["mime_type"] = m.MimeType
	}
	if m.ExpiresAt != "" {
		out["expires_at"] = m.ExpiresAt
	}
	if m.WebAuthnCredentialPublicID != "" {
		out["webauthn_credential_public_id"] = m.WebAuthnCredentialPublicID
	}
	return out
}

func (s *CryptbinStorage) IsExpired(m *CryptbinMeta) bool {
	if m.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

func (s *CryptbinStorage) tempPath(id, ext string) (string, error) {
	rb := make([]byte, 6)
	if _, err := rand.Read(rb); err != nil {
		return "", err
	}
	hex := fmt.Sprintf("%x", rb)
	return filepath.Join(s.basePath, "."+id+"."+hex+"."+ext+".tmp"), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// ─── KEK service ────────────────────────────────────────────────────────────
//
// Compatible with the PHP CryptbinKekService implementation: XChaCha20-Poly1305-IETF
// with a 32-byte raw KEK (NOT hashed) and AAD bound to the cryptbin ID via the
// label "cryptbin:dek-wrap:v1:<id>". This is symmetric with PHP libsodium output.

const wrappedDEKAlg = "XCHACHA20POLY1305-IETF"

type CryptbinKEK struct {
	key     []byte
	version string
}

func NewCryptbinKEK() (*CryptbinKEK, error) {
	cfg := config.Get()
	if cfg.CryptbinKEKBase64 == "" {
		return nil, errors.New("CRYPTBIN_KEK_BASE64 not configured")
	}
	key, err := base64.StdEncoding.DecodeString(cfg.CryptbinKEKBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid KEK base64: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("CRYPTBIN_KEK_BASE64 must decode to %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	version := cfg.CryptbinKEKVersion
	if version == "" {
		version = "v1"
	}
	return &CryptbinKEK{key: key, version: version}, nil
}

func (k *CryptbinKEK) Version() string { return k.version }

func (k *CryptbinKEK) aad(id string) []byte {
	return []byte("cryptbin:dek-wrap:v1:" + id)
}

// WrapDEK seals a 32-byte DEK with XChaCha20-Poly1305-IETF using a fresh nonce.
// The result is a map matching the PHP wire format.
func (k *CryptbinKEK) WrapDEK(dek []byte, id string) (map[string]string, error) {
	if len(dek) != 32 {
		return nil, errors.New("DEK must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	wrapped := aead.Seal(nil, nonce, dek, k.aad(id))
	return map[string]string{
		"wrapped_dek":       base64.RawURLEncoding.EncodeToString(wrapped),
		"wrapped_dek_nonce": base64.RawURLEncoding.EncodeToString(nonce),
		"wrapped_dek_alg":   wrappedDEKAlg,
		"kek_version":       k.version,
	}, nil
}

// UnwrapDEK takes the wrapped-DEK fields off a CryptbinMeta and returns the
// raw 32-byte DEK on success.
func (k *CryptbinKEK) UnwrapDEK(meta *CryptbinMeta, id string) ([]byte, error) {
	if meta.WrappedDEKAlg != wrappedDEKAlg {
		return nil, fmt.Errorf("unsupported wrapped DEK algorithm: %q", meta.WrappedDEKAlg)
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(meta.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("invalid wrapped_dek encoding: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(meta.WrappedDEKNonce)
	if err != nil {
		return nil, fmt.Errorf("invalid wrapped_dek_nonce encoding: %w", err)
	}
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("wrapped_dek_nonce length mismatch")
	}
	dek, err := aead.Open(nil, nonce, wrapped, k.aad(id))
	if err != nil {
		return nil, fmt.Errorf("DEK unwrap failed: %w", err)
	}
	if len(dek) != 32 {
		return nil, errors.New("unwrapped DEK has unexpected length")
	}
	return dek, nil
}

// ─── Key verifier ──────────────────────────────────────────────────────────
//
// PHP uses password_hash() with PASSWORD_ARGON2ID, which produces a
// `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>` PHC string. We reproduce
// that format so verifiers written by either implementation interoperate.

// Argon2id defaults matching PHP's PASSWORD_ARGON2ID defaults.
const (
	argon2Memory  uint32 = 65536 // 64 MiB
	argon2Time    uint32 = 4
	argon2Threads uint8  = 1
	argon2KeyLen  uint32 = 32
	argon2SaltLen uint32 = 16
)

// CryptbinValidateKeyMaterial returns true if keyB64 is a base64url-encoded 32-byte key.
func CryptbinValidateKeyMaterial(keyB64URL string) bool {
	if keyB64URL == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(keyB64URL)
	if err != nil {
		return false
	}
	return len(decoded) == 32
}

// CryptbinCreateVerifier hashes keyB64URL with Argon2id and returns a PHC-format
// verifier string compatible with PHP password_verify().
func CryptbinCreateVerifier(keyB64URL string) (string, error) {
	if !CryptbinValidateKeyMaterial(keyB64URL) {
		return "", errors.New("invalid key material")
	}
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(keyB64URL), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads, saltB64, hashB64), nil
}

// CryptbinVerifyKey checks keyB64URL against a PHC-format Argon2id verifier.
func CryptbinVerifyKey(keyB64URL, verifier string) bool {
	if keyB64URL == "" || verifier == "" {
		return false
	}
	if !CryptbinValidateKeyMaterial(keyB64URL) {
		return false
	}
	parts := strings.Split(verifier, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	if parts[2] != "v=19" {
		return false
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	if memory != argon2Memory || time != argon2Time || threads != argon2Threads {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != int(argon2SaltLen) {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != int(argon2KeyLen) {
		return false
	}
	got := argon2.IDKey([]byte(keyB64URL), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(expected, got) == 1
}

// AllowedMimeType returns true if the given MIME is in the configured allow-list,
// or if the allow-list is empty.
func AllowedMimeType(mime string) bool {
	allowed := strings.TrimSpace(config.Get().CryptbinAllowedMime)
	if allowed == "" {
		return true
	}
	mime = strings.ToLower(strings.TrimSpace(mime))
	for _, m := range strings.Split(allowed, ",") {
		if strings.ToLower(strings.TrimSpace(m)) == mime {
			return true
		}
	}
	return false
}
