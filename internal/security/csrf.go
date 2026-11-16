// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"blackwall/internal/config"
)

const csrfSessionKey = "_csrf_tokens"

func GenerateCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	sess, err := GetSession(w, r)
	if err != nil {
		return "", err
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	tokenHex := hex.EncodeToString(token)
	tokenHash := csrfHash(tokenHex)

	tokens, _ := sess.Get(csrfSessionKey).([]string)
	tokens = append(tokens, tokenHash)
	if len(tokens) > 20 {
		tokens = tokens[len(tokens)-20:]
	}
	sess.Set(csrfSessionKey, tokens)
	if err := sess.Save(); err != nil {
		return "", err
	}

	return tokenHex, nil
}

func ValidateCSRFToken(w http.ResponseWriter, r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	sess, err := GetSession(w, r)
	if err != nil {
		return false
	}

	tokenHash := csrfHash(token)
	tokens, _ := sess.Get(csrfSessionKey).([]string)
	for i, stored := range tokens {
		if hmac.Equal([]byte(stored), []byte(tokenHash)) {
			tokens = append(tokens[:i], tokens[i+1:]...)
			sess.Set(csrfSessionKey, tokens)
			_ = sess.Save()
			return true
		}
	}
	return false
}

// GenerateCSRF generates a CSRF token and stores it in the given session.
func GenerateCSRF(sess *Session) string {
	token := make([]byte, 32)
	rand.Read(token)
	tokenHex := hex.EncodeToString(token)
	tokenHash := csrfHash(tokenHex)

	tokens, _ := sess.Get(csrfSessionKey).([]string)
	tokens = append(tokens, tokenHash)
	if len(tokens) > 20 {
		tokens = tokens[len(tokens)-20:]
	}
	sess.Set(csrfSessionKey, tokens)
	return tokenHex
}

// ValidateCSRF validates a CSRF token against the given session (single-use).
func ValidateCSRF(sess *Session, token string) bool {
	if token == "" {
		return false
	}
	tokenHash := csrfHash(token)
	tokens, _ := sess.Get(csrfSessionKey).([]string)
	for i, stored := range tokens {
		if hmac.Equal([]byte(stored), []byte(tokenHash)) {
			tokens = append(tokens[:i], tokens[i+1:]...)
			sess.Set(csrfSessionKey, tokens)
			return true
		}
	}
	return false
}

func csrfHash(token string) string {
	key := config.Get().CSRFSecret
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}
