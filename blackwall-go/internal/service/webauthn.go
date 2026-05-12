package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"blackwall/internal/config"
)

type WebAuthnService struct {
	db     *sql.DB
	rpID   string
	rpName string
}

func NewWebAuthnService(db *sql.DB) *WebAuthnService {
	cfg := config.Get()
	return &WebAuthnService{
		db:     db,
		rpID:   cfg.WebAuthnRPID,
		rpName: cfg.WebAuthnRPName,
	}
}

type WebAuthnCredential struct {
	ID              int
	UserID          int
	CredentialID    string
	PublicKey       string
	AAGUID          sql.NullString
	SignCounter     int
	Label           sql.NullString
	Transports      sql.NullString
	AttestationType string
	CreatedAt       time.Time
	LastUsedAt      sql.NullTime
}

func (s *WebAuthnService) GenerateRegistrationOptions(userUUID, userName string) map[string]interface{} {
	challenge := make([]byte, 32)
	cryptoRandRead(challenge)

	return map[string]interface{}{
		"challenge": base64.StdEncoding.EncodeToString(challenge),
		"rp": map[string]interface{}{
			"name": s.rpName,
			"id":   s.rpID,
		},
		"user": map[string]interface{}{
			"id":          base64.StdEncoding.EncodeToString([]byte(userUUID)),
			"name":        userName,
			"displayName": userName,
		},
		"pubKeyCredParams": []map[string]interface{}{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257},  // RS256
		},
		"timeout":     60000,
		"attestation": "none",
		"authenticatorSelection": map[string]interface{}{
			"residentKey":        "required",
			"requireResidentKey": true,
			"userVerification":   "preferred",
		},
	}
}

func (s *WebAuthnService) GenerateAuthenticationOptions(userID int) (map[string]interface{}, error) {
	challenge := make([]byte, 32)
	cryptoRandRead(challenge)

	creds, err := s.GetUserCredentials(userID)
	if err != nil {
		return nil, err
	}

	allowCredentials := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		allowCredentials = append(allowCredentials, map[string]interface{}{
			"type": "public-key",
			"id":   c.CredentialID,
		})
	}

	return map[string]interface{}{
		"challenge":        base64.StdEncoding.EncodeToString(challenge),
		"timeout":          60000,
		"rpId":             s.rpID,
		"allowCredentials": allowCredentials,
		"userVerification": "preferred",
	}, nil
}

func (s *WebAuthnService) VerifyRegistrationResponse(clientDataJSONb64, expectedChallenge string) bool {
	clientDataBytes := b64urlDecode(clientDataJSONb64)
	if clientDataBytes == nil {
		clientDataBytes, _ = base64.StdEncoding.DecodeString(clientDataJSONb64)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return false
	}
	if clientData.Type != "webauthn.create" {
		return false
	}
	clientChallenge := b64urlDecode(clientData.Challenge)
	serverChallenge, _ := base64.StdEncoding.DecodeString(expectedChallenge)
	if subtle.ConstantTimeCompare(clientChallenge, serverChallenge) != 1 {
		return false
	}
	expectedOrigin := "https://" + s.rpID
	if subtle.ConstantTimeCompare([]byte(clientData.Origin), []byte(expectedOrigin)) != 1 {
		return false
	}
	return true
}

func (s *WebAuthnService) ExtractPublicKeyFromAttestation(attestationObjectB64 string) (credentialID string, publicKeyB64 string, signCounter int, err error) {
	attObjBytes := b64urlDecode(attestationObjectB64)
	if attObjBytes == nil {
		attObjBytes, _ = base64.StdEncoding.DecodeString(attestationObjectB64)
	}
	if len(attObjBytes) == 0 {
		return "", "", 0, fmt.Errorf("empty attestation object")
	}

	var attObj map[interface{}]interface{}
	if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
		return "", "", 0, fmt.Errorf("CBOR decode attestation: %w", err)
	}

	authDataRaw, ok := attObj["authData"]
	if !ok {
		return "", "", 0, fmt.Errorf("no authData")
	}
	authData, ok := authDataRaw.([]byte)
	if !ok {
		return "", "", 0, fmt.Errorf("authData not bytes")
	}
	if len(authData) < 37 {
		return "", "", 0, fmt.Errorf("authData too short")
	}

	// signCount at offset 33 (4 bytes, big-endian)
	signCounter = int(authData[33])<<24 | int(authData[34])<<16 | int(authData[35])<<8 | int(authData[36])

	// AT flag (bit 6 of flags byte at offset 32)
	flags := authData[32]
	if flags&0x40 == 0 {
		return "", "", 0, fmt.Errorf("AT flag not set")
	}

	offset := 37
	// AAGUID: 16 bytes
	offset += 16
	if offset+2 > len(authData) {
		return "", "", 0, fmt.Errorf("authData too short for credIdLen")
	}
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	if offset+credIDLen > len(authData) {
		return "", "", 0, fmt.Errorf("authData too short for credID")
	}
	credIDBytes := authData[offset : offset+credIDLen]
	credentialID = base64.RawURLEncoding.EncodeToString(credIDBytes)
	offset += credIDLen

	coseKeyBytes := authData[offset:]
	if len(coseKeyBytes) == 0 {
		return "", "", 0, fmt.Errorf("no COSE key bytes")
	}
	publicKeyB64 = base64.StdEncoding.EncodeToString(coseKeyBytes)
	return credentialID, publicKeyB64, signCounter, nil
}

func (s *WebAuthnService) VerifyAssertion(credentialID, clientDataJSONb64, authenticatorDataB64, signatureB64, expectedChallenge string) bool {
	cred, err := s.GetCredentialByID(credentialID)
	if err != nil || cred == nil {
		return false
	}

	// Decode clientDataJSON
	clientDataBytes := b64urlDecode(clientDataJSONb64)
	if clientDataBytes == nil {
		clientDataBytes, _ = base64.StdEncoding.DecodeString(clientDataJSONb64)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return false
	}
	if clientData.Type != "webauthn.get" {
		return false
	}

	// Verify challenge (constant-time)
	clientChallenge := b64urlDecode(clientData.Challenge)
	serverChallenge, _ := base64.StdEncoding.DecodeString(expectedChallenge)
	if subtle.ConstantTimeCompare(clientChallenge, serverChallenge) != 1 {
		return false
	}

	// Verify origin (constant-time)
	expectedOrigin := "https://" + s.rpID
	if subtle.ConstantTimeCompare([]byte(clientData.Origin), []byte(expectedOrigin)) != 1 {
		return false
	}

	// Decode authenticator data
	authData := b64urlDecode(authenticatorDataB64)
	if authData == nil {
		authData, _ = base64.StdEncoding.DecodeString(authenticatorDataB64)
	}
	if len(authData) < 37 {
		return false
	}

	// Verify RP ID hash (constant-time)
	rpIDHash := sha256.Sum256([]byte(s.rpID))
	if subtle.ConstantTimeCompare(authData[:32], rpIDHash[:]) != 1 {
		return false
	}

	// Check UP flag (bit 0) — user actively interacted with the authenticator
	// AND UV flag (bit 2) — user verified themselves (PIN/biometric).
	// Both are required to match PHP WebAuthnAssertionPolicy behaviour.
	flags := authData[32]
	if flags&0x01 == 0 {
		return false
	}
	if flags&0x04 == 0 {
		return false
	}

	// Verify signature
	clientDataHash := sha256.Sum256(clientDataBytes)
	signedData := append(authData, clientDataHash[:]...)

	sigBytes := b64urlDecode(signatureB64)
	if sigBytes == nil {
		sigBytes, _ = base64.StdEncoding.DecodeString(signatureB64)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cred.PublicKey)
	if err != nil {
		return false
	}

	if !verifyCOSESignature(pubKeyBytes, signedData, sigBytes) {
		return false
	}

	// Sign counter check matching WebAuthnAssertionPolicy::hasValidSignCounter:
	// authenticators that don't implement counters always report 0 (allowed),
	// but any non-zero counter must strictly increase to detect cloned tokens.
	newCounter := int(authData[33])<<24 | int(authData[34])<<16 | int(authData[35])<<8 | int(authData[36])
	if newCounter < 0 || cred.SignCounter < 0 {
		return false
	}
	if !(newCounter == 0 && cred.SignCounter == 0) && newCounter <= cred.SignCounter {
		return false
	}
	_, _ = s.db.Exec(`UPDATE webauthn_credentials SET sign_counter=?, last_used_at=NOW() WHERE id=?`, newCounter, cred.ID)

	return true
}

func verifyCOSESignature(coseKeyBytes, signedData, sig []byte) bool {
	var key map[interface{}]interface{}
	if err := cbor.Unmarshal(coseKeyBytes, &key); err != nil {
		return false
	}

	algRaw, ok := key[int64(3)]
	if !ok {
		algRaw = key[3]
	}
	var alg int64
	switch v := algRaw.(type) {
	case int64:
		alg = v
	case uint64:
		alg = int64(v)
	case int:
		alg = int64(v)
	}

	switch alg {
	case -7: // ES256
		return verifyES256(key, signedData, sig)
	case -257: // RS256
		return verifyRS256(key, signedData, sig)
	}
	return false
}

func verifyES256(key map[interface{}]interface{}, data, sig []byte) bool {
	getBytes := func(k interface{}) []byte {
		if v, ok := key[k]; ok {
			if b, ok := v.([]byte); ok {
				return b
			}
		}
		return nil
	}
	xBytes := getBytes(int64(-2))
	if xBytes == nil {
		xBytes = getBytes(-2)
	}
	yBytes := getBytes(int64(-3))
	if yBytes == nil {
		yBytes = getBytes(-3)
	}
	if xBytes == nil || yBytes == nil {
		return false
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// Parse DER-encoded signature
	var esig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		// Try raw r||s (64 bytes)
		if len(sig) == 64 {
			esig.R = new(big.Int).SetBytes(sig[:32])
			esig.S = new(big.Int).SetBytes(sig[32:])
		} else {
			return false
		}
	}

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], esig.R, esig.S)
}

func verifyRS256(key map[interface{}]interface{}, data, sig []byte) bool {
	getBytes := func(k interface{}) []byte {
		if v, ok := key[k]; ok {
			if b, ok := v.([]byte); ok {
				return b
			}
		}
		return nil
	}
	nBytes := getBytes(int64(-1))
	if nBytes == nil {
		nBytes = getBytes(-1)
	}
	eBytes := getBytes(int64(-2))
	if eBytes == nil {
		eBytes = getBytes(-2)
	}
	if nBytes == nil || eBytes == nil {
		return false
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false
	}
	rsaPub, ok := parsedPub.(*rsa.PublicKey)
	if !ok {
		return false
	}

	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(rsaPub, 0, hash[:], sig) == nil
}

func (s *WebAuthnService) StoreCredential(userID int, credentialID, publicKey string, signCounter int, label string) (int64, error) {
	result, err := s.db.Exec(
		`INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_counter, attestation_type, label) VALUES (?, ?, ?, ?, 'none', ?)`,
		userID, credentialID, publicKey, signCounter, nullString(label))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *WebAuthnService) GetUserCredentials(userID int) ([]*WebAuthnCredential, error) {
	rows, err := s.db.Query(`SELECT id, user_id, credential_id, public_key, aaguid, sign_counter, label, transports, attestation_type, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*WebAuthnCredential
	for rows.Next() {
		c := &WebAuthnCredential{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AAGUID, &c.SignCounter, &c.Label, &c.Transports, &c.AttestationType, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (s *WebAuthnService) GetCredentialByID(credentialID string) (*WebAuthnCredential, error) {
	c := &WebAuthnCredential{}
	err := s.db.QueryRow(`SELECT id, user_id, credential_id, public_key, aaguid, sign_counter, label, transports, attestation_type, created_at, last_used_at FROM webauthn_credentials WHERE credential_id = ?`, credentialID).
		Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AAGUID, &c.SignCounter, &c.Label, &c.Transports, &c.AttestationType, &c.CreatedAt, &c.LastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *WebAuthnService) DeleteCredential(credentialID int) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id=?`, credentialID)
	return err
}

func (s *WebAuthnService) GetCredentialByPublicID(publicID string) (*WebAuthnCredential, error) {
	return s.GetCredentialByID(publicID)
}

func (s *WebAuthnService) DB() *sql.DB { return s.db }
func (s *WebAuthnService) RPID() string { return s.rpID }

func b64urlDecode(s string) []byte {
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
