package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// PKCE per RFC 7636: code verifier is 43-128 characters from the unreserved
// URI character set (ALPHA / DIGIT / "-" / "." / "_" / "~"). The method
// identifier is case-sensitive and only "S256" is permitted (we do not
// accept the legacy "plain" method).
var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// ValidatePKCE returns true if codeVerifier hashes to codeChallenge under S256.
// The method string is compared case-sensitively as RFC 7636 §4.3 requires.
func ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" {
		return false
	}
	if !pkceVerifierPattern.MatchString(codeVerifier) {
		return false
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}
