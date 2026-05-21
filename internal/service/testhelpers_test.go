package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// hmacHexImpl is the canonical "HMAC-SHA256 → hex" the dispatcher uses,
// re-exposed for tests so they don't reach into private helpers in
// production code.
func hmacHexImpl(secret, message string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}
