package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// OIDCClaimsService manages two layers of custom OIDC claims merged into
// every ID token and /oauth/userinfo response:
//
//  1. **User-level** (`user_oidc_claims`) — apply to every token issued for
//     the user, regardless of project.
//  2. **Project-scoped** (`user_project_oidc_claims`) — apply only when the
//     token is issued in the context of that specific project; merged ON TOP
//     of the user-level claims so a project can override a user-wide value.
//
// We refuse to write OIDC-reserved claim names (sub, iss, aud, etc.) so a
// custom claim can't shadow a security-critical one. Values are stored as
// strings; if the operator provides JSON, we'll parse it back as the typed
// shape on read so booleans/numbers/objects round-trip.
type OIDCClaimsService struct {
	db *sql.DB
}

func NewOIDCClaimsService(db *sql.DB) *OIDCClaimsService {
	return &OIDCClaimsService{db: db}
}

// reservedClaims are claim names we refuse to allow as custom values to keep
// the issued tokens spec-compliant. RFC 7519 + OIDC Core require precise
// semantics for these — operator-supplied values would create attack surface.
var reservedClaims = map[string]bool{
	"iss":         true,
	"sub":         true,
	"aud":         true,
	"exp":         true,
	"iat":         true,
	"nbf":         true,
	"jti":         true,
	"nonce":       true,
	"at_hash":     true,
	"c_hash":      true,
	"auth_time":   true,
	"acr":         true,
	"amr":         true,
	"azp":         true,
	"scope":       true,
	"client_id":   true,
	"token_type":  true,
	"expires_in":  true,
	"project_id":  true,
}

// validClaimKey matches the conservative subset of valid JSON / OIDC claim
// names: lowercase + digits + underscore, must start with a letter, max 80
// chars. This is stricter than the JWT spec but avoids confusing punctuation
// and aligns with established conventions like `email`, `preferred_username`.
var validClaimKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)

// ValidateClaimKey returns nil if the key is allowed for custom storage.
func ValidateClaimKey(key string) error {
	if !validClaimKey.MatchString(key) {
		return errors.New("claim key must match [a-z][a-z0-9_]{0,79}")
	}
	if reservedClaims[key] {
		return errors.New("claim key is reserved by the OIDC/JWT spec")
	}
	return nil
}

// SetUserClaim upserts a user-level custom claim. Value may be a JSON
// literal (e.g. `123`, `true`, `["a","b"]`) or a plain string.
func (s *OIDCClaimsService) SetUserClaim(userID int, key, value string) error {
	if err := ValidateClaimKey(key); err != nil {
		return err
	}
	if len(value) > 4096 {
		return errors.New("claim value must be 4096 bytes or fewer")
	}
	_, err := s.db.Exec(`INSERT INTO user_oidc_claims (user_id, claim_key, claim_value)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE claim_value = VALUES(claim_value)`,
		userID, key, value)
	return err
}

// DeleteUserClaim removes a user-level claim. No-op if the key isn't set.
func (s *OIDCClaimsService) DeleteUserClaim(userID int, key string) error {
	_, err := s.db.Exec(`DELETE FROM user_oidc_claims WHERE user_id=? AND claim_key=?`, userID, key)
	return err
}

// ListUserClaims returns every user-level claim for the user.
func (s *OIDCClaimsService) ListUserClaims(userID int) ([]OIDCClaim, error) {
	return s.queryClaims(`SELECT claim_key, claim_value, updated_at
		FROM user_oidc_claims WHERE user_id=? ORDER BY claim_key`, userID)
}

// SetProjectClaim upserts a project-scoped claim for the given user/project.
func (s *OIDCClaimsService) SetProjectClaim(userID, projectID int, key, value string) error {
	if err := ValidateClaimKey(key); err != nil {
		return err
	}
	if len(value) > 4096 {
		return errors.New("claim value must be 4096 bytes or fewer")
	}
	_, err := s.db.Exec(`INSERT INTO user_project_oidc_claims (user_id, project_id, claim_key, claim_value)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE claim_value = VALUES(claim_value)`,
		userID, projectID, key, value)
	return err
}

// DeleteProjectClaim removes a project-scoped claim. No-op if not set.
func (s *OIDCClaimsService) DeleteProjectClaim(userID, projectID int, key string) error {
	_, err := s.db.Exec(`DELETE FROM user_project_oidc_claims
		WHERE user_id=? AND project_id=? AND claim_key=?`, userID, projectID, key)
	return err
}

// ListProjectClaims returns every project-scoped claim for the user/project.
func (s *OIDCClaimsService) ListProjectClaims(userID, projectID int) ([]OIDCClaim, error) {
	return s.queryClaims(`SELECT claim_key, claim_value, updated_at
		FROM user_project_oidc_claims WHERE user_id=? AND project_id=? ORDER BY claim_key`,
		userID, projectID)
}

// MergedClaims returns the effective claim set for tokens issued to userID in
// the context of projectID. User-level claims form the base; project-level
// claims overlay (a project setting wins over a user-wide setting with the
// same key). Values are decoded into typed shapes so JSON booleans / numbers
// / arrays round-trip correctly into the JWT.
func (s *OIDCClaimsService) MergedClaims(userID, projectID int) (map[string]interface{}, error) {
	out := map[string]interface{}{}

	userClaims, err := s.ListUserClaims(userID)
	if err != nil {
		return nil, err
	}
	for _, c := range userClaims {
		out[c.Key] = decodeClaimValue(c.Value)
	}

	if projectID > 0 {
		projectClaims, err := s.ListProjectClaims(userID, projectID)
		if err != nil {
			return nil, err
		}
		for _, c := range projectClaims {
			out[c.Key] = decodeClaimValue(c.Value)
		}
	}

	return out, nil
}

// OIDCClaim is one stored claim row.
type OIDCClaim struct {
	Key       string
	Value     string
	UpdatedAt sql.NullTime
}

func (s *OIDCClaimsService) queryClaims(q string, args ...interface{}) ([]OIDCClaim, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OIDCClaim
	for rows.Next() {
		var c OIDCClaim
		if err := rows.Scan(&c.Key, &c.Value, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeClaimValue tries to interpret value as a JSON literal so booleans,
// numbers, arrays, and objects are emitted with the correct JSON type. If
// parsing fails, the raw string is returned — the operator may have stored
// a plain string without JSON quoting, which is the common case.
func decodeClaimValue(value string) interface{} {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	// Quick reject for obviously non-JSON shapes; saves an Unmarshal call on
	// the common "Engineering" / "uk" / "alice@example.com" cases.
	switch trimmed[0] {
	case '{', '[', '"', 't', 'f', 'n', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var parsed interface{}
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
			return parsed
		}
	}
	return value
}
