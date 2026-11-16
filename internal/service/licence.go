// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"blackwall/internal/config"
)

const (
	licenceEnvelopeVersion = "BWLIC1"
	licenceAudience        = "blackwall-licence"
	maximumLicenceSize     = 16 * 1024
	maximumPayloadSize     = 8 * 1024
)

// LicenceEntity identifies the legal person or business to whom a licence was
// issued. Reference is an operator-defined customer or company number and must
// not contain secret material.
type LicenceEntity struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Reference string `json:"reference,omitempty"`
}

// LicenceClaims is the complete, versioned statement covered by the Ed25519
// signature. Integer timestamps are Unix seconds to keep validation identical
// across languages and independent of locale.
type LicenceClaims struct {
	Version            int           `json:"v"`
	LicenceID          string        `json:"licence_id"`
	Issuer             string        `json:"iss"`
	Audience           string        `json:"aud"`
	ProjectUUID        string        `json:"project_uuid"`
	Entity             LicenceEntity `json:"entity"`
	Hostnames          []string      `json:"hostnames"`
	Features           []string      `json:"features"`
	MaxInstances       int           `json:"max_instances"`
	IssuedAt           int64         `json:"iat"`
	NotBefore          int64         `json:"nbf"`
	ExpiresAt          int64         `json:"exp"`
	KeyID              string        `json:"kid"`
	StatusURL          string        `json:"status_url"`
	OnlineCheckSeconds int           `json:"online_check_seconds"`
}

// LicenceIssueRequest is the validated input boundary used by both the admin
// UI and future automation endpoints.
type LicenceIssueRequest struct {
	ProjectID       int
	ProjectUUID     string
	EntityType      string
	EntityName      string
	EntityReference string
	Hostnames       []string
	Features        []string
	MaxInstances    int
	ValidityDays    int
	IssuedByUserID  int
}

// ProjectLicence is persisted metadata. Token is populated only by Issue and
// GetToken; list operations never copy full licence material unnecessarily.
type ProjectLicence struct {
	ID               int64
	PublicID         string
	ProjectID        int
	EntityType       string
	EntityName       string
	EntityReference  sql.NullString
	Hostnames        []string
	Features         []string
	MaxInstances     int
	NotBefore        time.Time
	ExpiresAt        time.Time
	IssuedAt         time.Time
	IssuedByUserID   sql.NullInt64
	RevokedAt        sql.NullTime
	RevokedByUserID  sql.NullInt64
	RevocationReason sql.NullString
	SigningKeyID     string
	Token            string
}

func (l ProjectLicence) State(now time.Time) string {
	if l.RevokedAt.Valid {
		return "revoked"
	}
	if now.After(l.ExpiresAt) {
		return "expired"
	}
	if now.Before(l.NotBefore) {
		return "scheduled"
	}
	return "active"
}

// LicenceVerification is deliberately small and safe to return from the
// public status endpoint. Detailed parser and database errors remain server-side.
type LicenceVerification struct {
	Valid     bool           `json:"valid"`
	Code      string         `json:"code"`
	CheckedAt string         `json:"checked_at"`
	Claims    *LicenceClaims `json:"claims,omitempty"`
}

// LicencePublicKey is the non-secret key registry representation used by the
// well-known endpoint. X is the RFC 8037 base64url public-key value.
type LicencePublicKey struct {
	KeyType     string `json:"kty"`
	Curve       string `json:"crv"`
	Algorithm   string `json:"alg"`
	Use         string `json:"use"`
	KeyID       string `json:"kid"`
	X           string `json:"x"`
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint_sha256"`
}

// LicenceService owns signing, persistence, rotation registration, and online
// verification. The private key remains only in process memory and is never
// returned by this type.
type LicenceService struct {
	db                 *sql.DB
	issuer             string
	privateKey         ed25519.PrivateKey
	publicKey          ed25519.PublicKey
	keyID              string
	maxValidityDays    int
	clockSkew          time.Duration
	onlineCheckSeconds int
	now                func() time.Time
}

// NewLicenceService loads an optional dedicated Ed25519 signing key. A blank
// key path leaves verification endpoints available but disables new issuance;
// this preserves safe start-up for installations that have not enabled licences.
func NewLicenceService(db *sql.DB, cfg *config.Config) (*LicenceService, error) {
	s := &LicenceService{
		db:                 db,
		issuer:             strings.TrimRight(cfg.AppURL, "/"),
		maxValidityDays:    cfg.LicenceMaxValidityDays,
		clockSkew:          time.Duration(cfg.LicenceClockSkewSeconds) * time.Second,
		onlineCheckSeconds: cfg.LicenceOnlineCheckSeconds,
		now:                time.Now,
	}
	if strings.TrimSpace(cfg.LicenceSigningKeyFile) == "" {
		return s, nil
	}
	privateKey, err := loadLicencePrivateKey(cfg.LicenceSigningKeyFile)
	if err != nil {
		return nil, err
	}
	s.privateKey = privateKey
	s.publicKey = privateKey.Public().(ed25519.PublicKey)
	s.keyID = licenceKeyID(s.publicKey)
	if err := s.registerActiveKey(); err != nil {
		return nil, fmt.Errorf("register licence signing key: %w", err)
	}
	return s, nil
}

func (s *LicenceService) Enabled() bool {
	return len(s.privateKey) == ed25519.PrivateKeySize
}

// IssuanceReady confirms that the in-memory key is still active in the public
// registry. A key marked compromised stops issuance immediately, without
// waiting for a restart.
func (s *LicenceService) IssuanceReady() bool {
	if !s.Enabled() {
		return false
	}
	var status string
	return s.db.QueryRow(`SELECT status FROM licence_signing_keys WHERE kid=?`, s.keyID).Scan(&status) == nil && status == "active"
}

func (s *LicenceService) ActiveKeyID() string { return s.keyID }

func (s *LicenceService) Issuer() string { return s.issuer }

func (s *LicenceService) MaxValidityDays() int { return s.maxValidityDays }

func (s *LicenceService) registerActiveKey() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	encoded := base64.RawURLEncoding.EncodeToString(s.publicKey)
	var existingStatus string
	err = tx.QueryRow(`SELECT status FROM licence_signing_keys WHERE kid=?`, s.keyID).Scan(&existingStatus)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if existingStatus == "compromised" {
		return errors.New("refusing to reactivate a licence key marked compromised")
	}
	if _, err := tx.Exec(`UPDATE licence_signing_keys
		SET status='retired', retired_at=COALESCE(retired_at, NOW())
		WHERE status='active' AND kid<>?`, s.keyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO licence_signing_keys
		(kid, algorithm, public_key_base64, status)
		VALUES (?, 'Ed25519', ?, 'active')
		ON DUPLICATE KEY UPDATE
		algorithm='Ed25519', public_key_base64=VALUES(public_key_base64),
		status='active', retired_at=NULL`, s.keyID, encoded); err != nil {
		return err
	}
	return tx.Commit()
}

// Issue creates a signed licence and anchors the exact signed bytes in the
// database. No licence is returned unless persistence succeeds.
func (s *LicenceService) Issue(input LicenceIssueRequest) (*ProjectLicence, error) {
	if !s.IssuanceReady() {
		return nil, errors.New("licence issuance is disabled: no active signing key configured")
	}
	parsedProjectUUID, parseErr := uuid.Parse(input.ProjectUUID)
	if input.ProjectID < 1 || parseErr != nil || parsedProjectUUID.String() != input.ProjectUUID {
		return nil, errors.New("valid project required")
	}
	var projectStatus string
	if err := s.db.QueryRow(`SELECT status FROM projects WHERE id=? AND uuid=?`, input.ProjectID, input.ProjectUUID).Scan(&projectStatus); err != nil {
		return nil, errors.New("project not found")
	}
	if projectStatus != "active" {
		return nil, errors.New("licences can only be issued for an active project")
	}
	entity, err := normaliseLicenceEntity(input.EntityType, input.EntityName, input.EntityReference)
	if err != nil {
		return nil, err
	}
	hostnames, err := NormaliseLicenceHostnames(input.Hostnames)
	if err != nil {
		return nil, err
	}
	features, err := normaliseLicenceFeatures(input.Features)
	if err != nil {
		return nil, err
	}
	if input.MaxInstances < 1 || input.MaxInstances > 1_000_000 {
		return nil, errors.New("max_instances must be between 1 and 1000000")
	}
	if input.ValidityDays < 1 || input.ValidityDays > s.maxValidityDays {
		return nil, fmt.Errorf("validity_days must be between 1 and %d", s.maxValidityDays)
	}

	now := s.now().UTC().Truncate(time.Second)
	claims := LicenceClaims{
		Version:            1,
		LicenceID:          uuid.NewString(),
		Issuer:             s.issuer,
		Audience:           licenceAudience,
		ProjectUUID:        strings.ToLower(input.ProjectUUID),
		Entity:             entity,
		Hostnames:          hostnames,
		Features:           features,
		MaxInstances:       input.MaxInstances,
		IssuedAt:           now.Unix(),
		NotBefore:          now.Unix(),
		ExpiresAt:          now.Add(time.Duration(input.ValidityDays) * 24 * time.Hour).Unix(),
		KeyID:              s.keyID,
		StatusURL:          s.issuer + "/licences/v1/verify",
		OnlineCheckSeconds: s.onlineCheckSeconds,
	}
	token, payload, signature, err := SignLicence(s.privateKey, claims)
	if err != nil {
		return nil, err
	}
	hostnamesJSON, _ := json.Marshal(hostnames)
	featuresJSON, _ := json.Marshal(features)
	var entityReference interface{}
	if entity.Reference != "" {
		entityReference = entity.Reference
	}
	var issuedBy interface{}
	if input.IssuedByUserID > 0 {
		issuedBy = input.IssuedByUserID
	}
	res, err := s.db.Exec(`INSERT INTO project_licences
		(public_id, project_id, entity_type, entity_name, entity_reference,
		hostnames_json, features_json, max_instances, not_before, expires_at,
		issued_at, issued_by_user_id, signing_key_id, payload_json, signature_base64)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		claims.LicenceID, input.ProjectID, entity.Type, entity.Name, entityReference,
		string(hostnamesJSON), string(featuresJSON), input.MaxInstances,
		time.Unix(claims.NotBefore, 0).UTC(), time.Unix(claims.ExpiresAt, 0).UTC(), now,
		issuedBy, s.keyID, string(payload), base64.RawURLEncoding.EncodeToString(signature))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &ProjectLicence{
		ID: id, PublicID: claims.LicenceID, ProjectID: input.ProjectID,
		EntityType: entity.Type, EntityName: entity.Name,
		Hostnames: hostnames, Features: features, MaxInstances: input.MaxInstances,
		NotBefore: time.Unix(claims.NotBefore, 0).UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		IssuedAt: now, SigningKeyID: s.keyID, Token: token,
	}, nil
}

// ListForProject returns bounded licence metadata without loading signed token
// bodies. This keeps ordinary admin page requests from copying every token.
func (s *LicenceService) ListForProject(projectID int) ([]ProjectLicence, error) {
	if projectID < 1 {
		return nil, errors.New("valid project required")
	}
	rows, err := s.db.Query(`SELECT id, public_id, project_id, entity_type, entity_name,
		entity_reference, hostnames_json, features_json, max_instances,
		not_before, expires_at, issued_at, issued_by_user_id, revoked_at,
		revoked_by_user_id, revocation_reason, signing_key_id
		FROM project_licences WHERE project_id=?
		ORDER BY issued_at DESC, id DESC LIMIT 1000`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	licences := make([]ProjectLicence, 0)
	for rows.Next() {
		var licence ProjectLicence
		var hostnamesJSON, featuresJSON string
		if err := rows.Scan(
			&licence.ID, &licence.PublicID, &licence.ProjectID,
			&licence.EntityType, &licence.EntityName, &licence.EntityReference,
			&hostnamesJSON, &featuresJSON, &licence.MaxInstances,
			&licence.NotBefore, &licence.ExpiresAt, &licence.IssuedAt,
			&licence.IssuedByUserID, &licence.RevokedAt, &licence.RevokedByUserID,
			&licence.RevocationReason, &licence.SigningKeyID,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(hostnamesJSON), &licence.Hostnames); err != nil {
			return nil, fmt.Errorf("decode licence hostnames: %w", err)
		}
		if err := json.Unmarshal([]byte(featuresJSON), &licence.Features); err != nil {
			return nil, fmt.Errorf("decode licence features: %w", err)
		}
		licences = append(licences, licence)
	}
	return licences, rows.Err()
}

// GetToken reconstructs and cryptographically checks a stored token before it
// is downloaded again. Compromised-key tokens are deliberately not exported.
func (s *LicenceService) GetToken(projectID int, publicID string) (string, error) {
	if projectID < 1 || uuid.Validate(publicID) != nil {
		return "", sql.ErrNoRows
	}
	var payload, signatureText, encodedKey, keyStatus string
	err := s.db.QueryRow(`SELECT pl.payload_json, pl.signature_base64,
		lsk.public_key_base64, lsk.status
		FROM project_licences pl
		JOIN licence_signing_keys lsk ON lsk.kid=pl.signing_key_id
		WHERE pl.project_id=? AND pl.public_id=?`, projectID, publicID).
		Scan(&payload, &signatureText, &encodedKey, &keyStatus)
	if err != nil {
		return "", err
	}
	if keyStatus == "compromised" {
		return "", errors.New("licence signing key is compromised")
	}
	token := licenceEnvelopeVersion + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signatureText
	keyBytes, err := base64.RawURLEncoding.Strict().DecodeString(encodedKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return "", errors.New("stored licence public key is invalid")
	}
	if _, _, _, err := VerifyLicenceSignature(token, ed25519.PublicKey(keyBytes)); err != nil {
		return "", errors.New("stored licence failed signature verification")
	}
	return token, nil
}

// Revoke is idempotent only for a currently active row. Returning sql.ErrNoRows
// for an already-revoked or cross-project ID prevents a misleading success audit.
func (s *LicenceService) Revoke(projectID int, publicID string, actorUserID int, reason string) error {
	if projectID < 1 || actorUserID < 1 || uuid.Validate(publicID) != nil {
		return errors.New("valid project, licence, and actor required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 || containsControl(reason) || !utf8.ValidString(reason) {
		return errors.New("revocation reason must be valid text of between 1 and 500 bytes")
	}
	result, err := s.db.Exec(`UPDATE project_licences
		SET revoked_at=NOW(), revoked_by_user_id=?, revocation_reason=?
		WHERE project_id=? AND public_id=? AND revoked_at IS NULL`,
		actorUserID, reason, projectID, publicID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// SignLicence returns the transport token and the exact payload/signature
// bytes. It is exported so official validators can be tested against fixtures.
func SignLicence(privateKey ed25519.PrivateKey, claims LicenceClaims) (string, []byte, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", nil, nil, errors.New("invalid Ed25519 private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if claims.KeyID != licenceKeyID(publicKey) {
		return "", nil, nil, errors.New("licence claims kid does not match signing key")
	}
	if err := validateLicenceClaimShape(&claims); err != nil {
		return "", nil, nil, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, nil, err
	}
	if len(payload) > maximumPayloadSize {
		return "", nil, nil, errors.New("licence payload too large")
	}
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signed := licenceEnvelopeVersion + "." + payloadSegment
	signature := ed25519.Sign(privateKey, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), payload, signature, nil
}

// VerifyLicenceSignature performs strict envelope parsing, canonical JSON
// validation, key-ID binding, and Ed25519 verification. It does not check time,
// hostname, project, or revocation; callers must apply those policy checks too.
func VerifyLicenceSignature(token string, publicKey ed25519.PublicKey) (*LicenceClaims, []byte, []byte, error) {
	claims, payload, signature, signed, err := parseLicenceEnvelope(token)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize || claims.KeyID != licenceKeyID(publicKey) {
		return nil, nil, nil, errors.New("licence key does not match kid")
	}
	if !ed25519.Verify(publicKey, signed, signature) {
		return nil, nil, nil, errors.New("invalid licence signature")
	}
	return claims, payload, signature, nil
}

func parseLicenceEnvelope(token string) (*LicenceClaims, []byte, []byte, []byte, error) {
	token = strings.TrimSpace(token)
	if len(token) == 0 || len(token) > maximumLicenceSize {
		return nil, nil, nil, nil, errors.New("invalid licence size")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != licenceEnvelopeVersion || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, nil, errors.New("invalid licence envelope")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > maximumPayloadSize {
		return nil, nil, nil, nil, errors.New("invalid licence payload encoding")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, nil, nil, errors.New("invalid licence signature encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var claims LicenceClaims
	if err := decoder.Decode(&claims); err != nil {
		return nil, nil, nil, nil, errors.New("invalid licence claims")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, nil, nil, nil, errors.New("invalid trailing licence data")
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, nil, nil, nil, errors.New("non-canonical licence claims")
	}
	if err := validateLicenceClaimShape(&claims); err != nil {
		return nil, nil, nil, nil, err
	}
	return &claims, payload, signature, []byte(parts[0] + "." + parts[1]), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("additional JSON value")
	}
	return nil
}

func validateLicenceClaimShape(c *LicenceClaims) error {
	if c.Version != 1 || c.Audience != licenceAudience || uuid.Validate(c.LicenceID) != nil || uuid.Validate(c.ProjectUUID) != nil {
		return errors.New("invalid licence identity claims")
	}
	if parsed, _ := uuid.Parse(c.LicenceID); parsed.String() != c.LicenceID {
		return errors.New("non-canonical licence ID")
	}
	if parsed, _ := uuid.Parse(c.ProjectUUID); parsed.String() != c.ProjectUUID {
		return errors.New("non-canonical project UUID")
	}
	if c.Issuer == "" || len(c.Issuer) > 2048 || c.KeyID == "" || len(c.KeyID) > 64 {
		return errors.New("invalid licence issuer or key")
	}
	if c.StatusURL != strings.TrimRight(c.Issuer, "/")+"/licences/v1/verify" {
		return errors.New("invalid licence status URL")
	}
	if c.IssuedAt <= 0 || c.NotBefore < c.IssuedAt || c.ExpiresAt <= c.NotBefore {
		return errors.New("invalid licence timestamps")
	}
	if c.OnlineCheckSeconds < 300 || c.OnlineCheckSeconds > 604800 {
		return errors.New("invalid online check interval")
	}
	entity, err := normaliseLicenceEntity(c.Entity.Type, c.Entity.Name, c.Entity.Reference)
	if err != nil {
		return err
	}
	if entity != c.Entity {
		return errors.New("non-canonical licence entity")
	}
	hostnames, err := NormaliseLicenceHostnames(c.Hostnames)
	if err != nil || !stringSlicesEqual(hostnames, c.Hostnames) {
		return errors.New("invalid or non-canonical licence hostnames")
	}
	features, err := normaliseLicenceFeatures(c.Features)
	if err != nil || !stringSlicesEqual(features, c.Features) {
		return errors.New("invalid or non-canonical licence features")
	}
	if c.MaxInstances < 1 || c.MaxInstances > 1_000_000 {
		return errors.New("invalid max_instances")
	}
	return nil
}

// VerifyOnline combines cryptographic verification with issuer, project,
// hostname, time, key-status, database anchoring, and revocation checks.
func (s *LicenceService) VerifyOnline(token, expectedHostname, expectedProjectUUID string) LicenceVerification {
	now := s.now().UTC()
	failure := func(code string) LicenceVerification {
		return LicenceVerification{Valid: false, Code: code, CheckedAt: now.Format(time.RFC3339)}
	}
	claims, _, _, _, err := parseLicenceEnvelope(token)
	if err != nil {
		return failure("invalid_licence")
	}
	var encodedKey, keyStatus string
	if err := s.db.QueryRow(`SELECT public_key_base64, status FROM licence_signing_keys WHERE kid=?`, claims.KeyID).Scan(&encodedKey, &keyStatus); err != nil {
		return failure("invalid_licence")
	}
	keyBytes, err := base64.RawURLEncoding.Strict().DecodeString(encodedKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return failure("invalid_licence")
	}
	verifiedClaims, payload, signature, err := VerifyLicenceSignature(token, ed25519.PublicKey(keyBytes))
	if err != nil {
		return failure("invalid_licence")
	}
	if keyStatus == "compromised" {
		return failure("key_compromised")
	}
	if code := CheckLicenceClaims(verifiedClaims, s.issuer, expectedHostname, expectedProjectUUID, now, s.clockSkew); code != "valid" {
		return failure(code)
	}

	var storedPayload, storedSignature, projectStatus string
	var revokedAt sql.NullTime
	err = s.db.QueryRow(`SELECT pl.payload_json, pl.signature_base64, pl.revoked_at, p.status
		FROM project_licences pl JOIN projects p ON p.id=pl.project_id
		WHERE pl.public_id=? AND p.uuid=?`, verifiedClaims.LicenceID, verifiedClaims.ProjectUUID).
		Scan(&storedPayload, &storedSignature, &revokedAt, &projectStatus)
	if err != nil {
		return failure("not_recorded")
	}
	signatureText := base64.RawURLEncoding.EncodeToString(signature)
	if !hmac.Equal([]byte(storedPayload), payload) || !hmac.Equal([]byte(storedSignature), []byte(signatureText)) {
		return failure("record_mismatch")
	}
	if projectStatus != "active" {
		return failure("project_disabled")
	}
	if revokedAt.Valid {
		return failure("revoked")
	}
	return LicenceVerification{Valid: true, Code: "valid", CheckedAt: now.Format(time.RFC3339), Claims: verifiedClaims}
}

// CheckLicenceClaims applies the non-cryptographic validation policy shared by
// online and offline validators. It returns a stable machine-readable code.
// Signature verification must always happen before this function is called.
func CheckLicenceClaims(claims *LicenceClaims, expectedIssuer, expectedHostname, expectedProjectUUID string, now time.Time, clockSkew time.Duration) string {
	if claims == nil || validateLicenceClaimShape(claims) != nil {
		return "invalid_licence"
	}
	if claims.Issuer != strings.TrimRight(expectedIssuer, "/") {
		return "issuer_mismatch"
	}
	if uuid.Validate(expectedProjectUUID) != nil || !strings.EqualFold(claims.ProjectUUID, expectedProjectUUID) {
		return "project_mismatch"
	}
	hostname, err := NormaliseLicenceHostname(expectedHostname)
	if err != nil || !containsString(claims.Hostnames, hostname) {
		return "hostname_mismatch"
	}
	if clockSkew < 0 || clockSkew > 10*time.Minute {
		return "invalid_licence"
	}
	now = now.UTC()
	if now.Add(clockSkew).Unix() < claims.NotBefore {
		return "not_yet_valid"
	}
	if now.Add(-clockSkew).Unix() > claims.ExpiresAt {
		return "expired"
	}
	if claims.IssuedAt > now.Add(clockSkew).Unix() {
		return "invalid_licence"
	}
	return "valid"
}

func (s *LicenceService) PublicKeys() ([]LicencePublicKey, error) {
	rows, err := s.db.Query(`SELECT kid, public_key_base64, status FROM licence_signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]LicencePublicKey, 0)
	for rows.Next() {
		var kid, encoded, status string
		if err := rows.Scan(&kid, &encoded, &status); err != nil {
			return nil, err
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		sum := sha256.Sum256(raw)
		keys = append(keys, LicencePublicKey{
			KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig",
			KeyID: kid, X: encoded, Status: status,
			Fingerprint: "SHA256:" + base64.RawURLEncoding.EncodeToString(sum[:]),
		})
	}
	return keys, rows.Err()
}

func loadLicencePrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat licence signing key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("licence signing key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("licence signing key permissions must be 0600 or stricter, got %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read licence signing key: %w", err)
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("licence signing key must contain one PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse licence signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("licence signing key must be Ed25519")
	}
	return privateKey, nil
}

func licenceKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "bwlic_" + base64.RawURLEncoding.EncodeToString(sum[:18])
}

func normaliseLicenceEntity(entityType, name, reference string) (LicenceEntity, error) {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	name = strings.TrimSpace(name)
	reference = strings.TrimSpace(reference)
	if entityType != "person" && entityType != "business" {
		return LicenceEntity{}, errors.New("entity_type must be person or business")
	}
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || containsControl(name) {
		return LicenceEntity{}, errors.New("entity_name must be valid text of at most 255 bytes")
	}
	if len(reference) > 255 || !utf8.ValidString(reference) || containsControl(reference) {
		return LicenceEntity{}, errors.New("entity_reference must be valid text of at most 255 bytes")
	}
	return LicenceEntity{Type: entityType, Name: name, Reference: reference}, nil
}

// NormaliseLicenceHostnames validates, lower-cases, de-duplicates, and sorts
// exact DNS names or IP literals. Wildcards are deliberately unsupported:
// enumerating each authorised host avoids public-suffix and subdomain ambiguity.
func NormaliseLicenceHostnames(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > 32 {
		return nil, errors.New("between 1 and 32 hostnames are required")
	}
	set := make(map[string]struct{}, len(input))
	for _, raw := range input {
		host, err := NormaliseLicenceHostname(raw)
		if err != nil {
			return nil, err
		}
		set[host] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

func NormaliseLicenceHostname(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 || strings.Contains(host, "*") || strings.ContainsAny(host, "/\\@?#%") {
		return "", errors.New("invalid hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if !isASCII(host) || strings.Contains(host, ":") {
		return "", errors.New("hostname must be an ASCII DNS name or IP literal; use punycode for international names")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname label")
		}
		for _, c := range []byte(label) {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", errors.New("invalid DNS hostname character")
			}
		}
	}
	return host, nil
}

func normaliseLicenceFeatures(input []string) ([]string, error) {
	if len(input) > 64 {
		return nil, errors.New("at most 64 features are allowed")
	}
	set := make(map[string]struct{}, len(input))
	for _, raw := range input {
		feature := strings.ToLower(strings.TrimSpace(raw))
		if feature == "" {
			continue
		}
		if len(feature) > 80 || !validFeatureName(feature) {
			return nil, fmt.Errorf("invalid feature %q", raw)
		}
		set[feature] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for feature := range set {
		out = append(out, feature)
	}
	sort.Strings(out)
	return out, nil
}

func validFeatureName(s string) bool {
	for i, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (i > 0 && ((c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
			continue
		}
		return false
	}
	return len(s) > 0
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
