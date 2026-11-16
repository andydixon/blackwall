// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package security

import (
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"

	"blackwall/internal/model"
)

// AuthenticateOAuthClient implements RFC 6749 §2.3 client authentication for
// the token/revoke/introspect endpoints. It supports client_secret_basic,
// client_secret_post, and "none" (for public PKCE clients).
//
// Per §2.3.1 a client MUST NOT use more than one authentication method per
// request. We reject any request that mixes Basic auth with a body secret,
// or that supplies inconsistent client_ids in the two locations.
func AuthenticateOAuthClient(authHeader string, body map[string]string, findClient func(string) (*model.OAuthClient, error)) (*model.OAuthClient, string) {
	basicPresent, basicID, basicSecret, basicValid := parseBasicAuth(authHeader)

	if basicPresent && !basicValid {
		// Basic header was sent but malformed (bad scheme syntax / non-base64).
		return nil, "invalid_client"
	}

	bodyID := strings.TrimSpace(body["client_id"])
	bodySecret, bodySecretSet := body["client_secret"]

	// RFC 6749 §2.3.1: reject requests that present credentials in both
	// the Authorization header AND the request body.
	if basicPresent && bodySecretSet && bodySecret != "" {
		return nil, "invalid_client"
	}

	// If both locations carry a client_id they must agree.
	if basicPresent && bodyID != "" && subtle.ConstantTimeCompare([]byte(basicID), []byte(bodyID)) != 1 {
		return nil, "invalid_client"
	}

	clientID := basicID
	if clientID == "" {
		clientID = bodyID
	}
	if clientID == "" {
		return nil, "invalid_client"
	}

	client, err := findClient(clientID)
	if err != nil || client == nil || !client.IsActive() {
		return nil, "invalid_client"
	}

	if client.IsConfidential() {
		providedSecret := basicSecret
		if !basicPresent {
			providedSecret = bodySecret
		}
		if providedSecret == "" {
			return nil, "invalid_client"
		}
		secretHash := HashToken(providedSecret)
		if !ConstantTimeEqual(secretHash, client.ClientSecretHash.String) {
			return nil, "invalid_client"
		}
		return client, ""
	}

	// Public clients use token_endpoint_auth_method = "none".
	// Sending Basic auth or a body secret is a configuration mismatch.
	if basicPresent {
		return nil, "unauthorized_client"
	}
	if bodySecretSet && bodySecret != "" {
		return nil, "unauthorized_client"
	}
	return client, ""
}

// parseBasicAuth returns (present, clientID, clientSecret, valid). `present` is
// true if the header begins with "Basic " (case-insensitive); `valid` is true
// if the rest decodes to a "user:pass" pair.
func parseBasicAuth(header string) (present bool, clientID, clientSecret string, valid bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return false, "", "", false
	}
	if len(header) < 6 || !strings.EqualFold(header[:6], "Basic ") {
		return false, "", "", false
	}
	present = true
	encoded := strings.TrimSpace(header[6:])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return present, "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return present, "", "", false
	}
	return present, parts[0], parts[1], true
}

// ValidateScopeList returns the first scope not allowed by the client, or empty string.
func FirstDisallowedScope(requested, allowed []string) string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}
	for _, s := range requested {
		if !allowedSet[s] {
			return s
		}
	}
	return ""
}

// ValidateOAuthRequest validates a standard authorization request.
func ValidateOAuthRequest(params url.Values, isOIDC bool) (ok bool, errCode, errDesc string) {
	if params.Get("response_type") != "code" {
		return false, "unsupported_response_type", "Only 'code' response type is supported"
	}

	challenge := params.Get("code_challenge")
	if challenge == "" {
		return false, "invalid_request", "code_challenge is required"
	}
	if params.Get("code_challenge_method") != "S256" {
		return false, "invalid_request", "code_challenge_method must be S256"
	}

	if isOIDC && params.Get("nonce") == "" {
		return false, "invalid_request", "nonce is required for OpenID Connect requests"
	}
	if maxAgeValues, present := params["max_age"]; present {
		if !isOIDC {
			return false, "invalid_request", "max_age requires the openid scope"
		}
		if len(maxAgeValues) != 1 || maxAgeValues[0] == "" {
			return false, "invalid_request", "max_age must be a non-negative integer"
		}
		if _, err := strconv.ParseUint(maxAgeValues[0], 10, 63); err != nil {
			return false, "invalid_request", "max_age must be a non-negative integer"
		}
	}

	return true, "", ""
}
