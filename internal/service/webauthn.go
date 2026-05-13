package service

import (
	"crypto"
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
	"log"
	"math/big"
	"net/url"
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
	expectedOrigin := s.expectedOrigin()
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
	ok, _ := s.VerifyAssertionDetailed(credentialID, clientDataJSONb64, authenticatorDataB64, signatureB64, expectedChallenge)
	return ok
}

func (s *WebAuthnService) VerifyAssertionDetailed(credentialID, clientDataJSONb64, authenticatorDataB64, signatureB64, expectedChallenge string) (bool, string) {
	cred, err := s.GetCredentialByID(credentialID)
	if err != nil || cred == nil {
		return s.verifyFail("credential_not_found", credentialID, "stored credential missing")
	}

	// Decode clientDataJSON
	clientDataBytes := b64urlDecode(clientDataJSONb64)
	if clientDataBytes == nil {
		clientDataBytes, _ = base64.StdEncoding.DecodeString(clientDataJSONb64)
	}
	if len(clientDataBytes) == 0 {
		return s.verifyFail("client_data_decode_failed", credentialID, "clientDataJSON decode failed")
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return s.verifyFail("client_data_unmarshal_failed", credentialID, err.Error())
	}
	if clientData.Type != "webauthn.get" {
		return s.verifyFail("client_data_type_mismatch", credentialID, clientData.Type)
	}

	// Verify challenge (constant-time)
	clientChallenge := b64urlDecode(clientData.Challenge)
	serverChallenge, _ := base64.StdEncoding.DecodeString(expectedChallenge)
	if subtle.ConstantTimeCompare(clientChallenge, serverChallenge) != 1 {
		return s.verifyFail("challenge_mismatch", credentialID, fmt.Sprintf("client_len=%d server_len=%d", len(clientChallenge), len(serverChallenge)))
	}

	// Verify origin (constant-time)
	expectedOrigin := s.expectedOrigin()
	if subtle.ConstantTimeCompare([]byte(clientData.Origin), []byte(expectedOrigin)) != 1 {
		return s.verifyFail("origin_mismatch", credentialID, fmt.Sprintf("got=%q want=%q", clientData.Origin, expectedOrigin))
	}

	// Decode authenticator data
	authData := b64urlDecode(authenticatorDataB64)
	if authData == nil {
		authData, _ = base64.StdEncoding.DecodeString(authenticatorDataB64)
	}
	if len(authData) < 37 {
		return s.verifyFail("authenticator_data_too_short", credentialID, fmt.Sprintf("len=%d", len(authData)))
	}

	// Verify RP ID hash (constant-time)
	rpIDHash := sha256.Sum256([]byte(s.rpID))
	if subtle.ConstantTimeCompare(authData[:32], rpIDHash[:]) != 1 {
		return s.verifyFail("rp_id_hash_mismatch", credentialID, s.rpID)
	}

	// Check UP flag (bit 0) — user actively interacted with the authenticator
	// AND UV flag (bit 2) — user verified themselves (PIN/biometric).
	// Both are required to match PHP WebAuthnAssertionPolicy behaviour.
	flags := authData[32]
	if flags&0x01 == 0 {
		return s.verifyFail("user_presence_flag_not_set", credentialID, fmt.Sprintf("flags=0x%02x", flags))
	}
	if flags&0x04 == 0 {
		return s.verifyFail("user_verification_flag_not_set", credentialID, fmt.Sprintf("flags=0x%02x", flags))
	}

	// Verify signature
	clientDataHash := sha256.Sum256(clientDataBytes)
	signedData := append(authData, clientDataHash[:]...)

	sigBytes := b64urlDecode(signatureB64)
	if sigBytes == nil {
		sigBytes, _ = base64.StdEncoding.DecodeString(signatureB64)
	}
	if len(sigBytes) == 0 {
		return s.verifyFail("signature_decode_failed", credentialID, "signature bytes empty")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cred.PublicKey)
	if err != nil {
		return s.verifyFail("stored_public_key_decode_failed", credentialID, err.Error())
	}

	if !verifyCOSESignature(pubKeyBytes, signedData, sigBytes) {
		if config.Get().AppDebug {
			log.Printf(
				"webauthn signature debug: credential_id=%q challenge=%q client_data=%q authenticator_data=%q signature=%q public_key=%q",
				credentialID,
				expectedChallenge,
				clientDataJSONb64,
				authenticatorDataB64,
				signatureB64,
				cred.PublicKey,
			)
		}
		return s.verifyFail("signature_verification_failed", credentialID, fmt.Sprintf("sig_len=%d", len(sigBytes)))
	}

	// Sign counter check matching WebAuthnAssertionPolicy::hasValidSignCounter:
	// authenticators that don't implement counters always report 0 (allowed),
	// but any non-zero counter must strictly increase to detect cloned tokens.
	newCounter := int(authData[33])<<24 | int(authData[34])<<16 | int(authData[35])<<8 | int(authData[36])
	if newCounter < 0 || cred.SignCounter < 0 {
		return s.verifyFail("invalid_sign_counter", credentialID, fmt.Sprintf("stored=%d new=%d", cred.SignCounter, newCounter))
	}
	if !(newCounter == 0 && cred.SignCounter == 0) && newCounter <= cred.SignCounter {
		return s.verifyFail("sign_counter_regression", credentialID, fmt.Sprintf("stored=%d new=%d", cred.SignCounter, newCounter))
	}
	_, _ = s.db.Exec(`UPDATE webauthn_credentials SET sign_counter=?, last_used_at=NOW() WHERE id=?`, newCounter, cred.ID)

	return true, ""
}

func verifyCOSESignature(coseKeyBytes, signedData, sig []byte) bool {
	var key map[interface{}]interface{}
	if err := cbor.Unmarshal(coseKeyBytes, &key); err != nil {
		return false
	}

	algRaw, ok := getCOSEValue(key, 3)
	if !ok {
		return false
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
	getBytes := func(label int64) []byte {
		v, ok := getCOSEValue(key, label)
		if !ok {
			return nil
		}
		b, _ := v.([]byte)
		return b
	}
	xBytes := getBytes(-2)
	yBytes := getBytes(-3)
	if xBytes == nil || yBytes == nil {
		return false
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	hash := sha256.Sum256(data)

	// Most authenticators return ES256 signatures in ASN.1 DER form.
	// Verify that representation directly first; it avoids any ambiguity in
	// manual DER-to-raw conversion and matches the bytes the browser sent.
	if len(sig) != 64 {
		if ecdsa.VerifyASN1(pub, hash[:], sig) {
			return true
		}
		sig = convertDERToRaw(sig)
		if len(sig) != 64 {
			return false
		}
	}

	var esig struct{ R, S *big.Int }
	esig.R = new(big.Int).SetBytes(sig[:32])
	esig.S = new(big.Int).SetBytes(sig[32:])
	if ecdsa.Verify(pub, hash[:], esig.R, esig.S) {
		return true
	}

	// Some authenticators or middleware layers may still hand us DER after the
	// raw path above. Keep an ASN.1 parse fallback for compatibility.
	if _, err := asn1.Unmarshal(sig, &esig); err == nil {
		return ecdsa.Verify(pub, hash[:], esig.R, esig.S)
	}
	return false
}

func convertDERToRaw(der []byte) []byte {
	if len(der) < 8 || der[0] != 0x30 {
		return der
	}
	offset := 2
	if offset >= len(der) || der[offset] != 0x02 {
		return der
	}
	offset++
	if offset >= len(der) {
		return der
	}
	rLength := int(der[offset])
	offset++
	if offset+rLength > len(der) {
		return der
	}
	r := append([]byte(nil), der[offset:offset+rLength]...)
	offset += rLength

	if offset >= len(der) || der[offset] != 0x02 {
		return der
	}
	offset++
	if offset >= len(der) {
		return der
	}
	sLength := int(der[offset])
	offset++
	if offset+sLength > len(der) {
		return der
	}
	s := append([]byte(nil), der[offset:offset+sLength]...)

	for len(r) > 32 && r[0] == 0x00 {
		r = r[1:]
	}
	for len(s) > 32 && s[0] == 0x00 {
		s = s[1:]
	}
	if len(r) > 32 || len(s) > 32 {
		return der
	}

	raw := make([]byte, 64)
	copy(raw[32-len(r):32], r)
	copy(raw[64-len(s):], s)
	return raw
}

func verifyRS256(key map[interface{}]interface{}, data, sig []byte) bool {
	getBytes := func(label int64) []byte {
		v, ok := getCOSEValue(key, label)
		if !ok {
			return nil
		}
		b, _ := v.([]byte)
		return b
	}
	nBytes := getBytes(-1)
	eBytes := getBytes(-2)
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
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig) == nil
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

func (s *WebAuthnService) expectedOrigin() string {
	appURL := strings.TrimSpace(config.Get().AppURL)
	if appURL != "" {
		if parsed, err := url.Parse(appURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host
		}
	}
	return "https://" + s.rpID
}

func (s *WebAuthnService) verifyFail(reason, credentialID, detail string) (bool, string) {
	log.Printf("webauthn verify failed: reason=%s credential_id=%q detail=%s", reason, credentialID, detail)
	return false, reason
}

func getCOSEValue(key map[interface{}]interface{}, label int64) (interface{}, bool) {
	candidates := []interface{}{label, int(label)}
	if label >= 0 {
		candidates = append(candidates, uint64(label), uint(label))
	}
	for _, candidate := range candidates {
		if v, ok := key[candidate]; ok {
			return v, true
		}
	}
	return nil, false
}

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
