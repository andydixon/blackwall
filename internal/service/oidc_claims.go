package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// OIDCClaimsService manages four layers of custom OIDC claims merged into
// every ID token and /oauth/userinfo response, listed from broadest to
// narrowest (later layers overlay earlier ones with the same key):
//
//  1. **Org defaults** (`organization_oidc_claim_defaults`) — apply to every
//     token for any user in the organisation, regardless of project.
//  2. **Project defaults** (`project_oidc_claim_defaults`) — apply when the
//     token is bound to a specific project; merged on top of org defaults so
//     a project template can override an org-wide value.
//  3. **User-level** (`user_oidc_claims`) — per-user values that ride on
//     every token for that user, regardless of project. Override templates.
//  4. **User × project** (`user_project_oidc_claims`) — per-user overrides
//     scoped to a single project; the narrowest layer, wins over everything.
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

// SetOrgDefault upserts an organisation-level default claim. Applies to every
// token issued for any user in the org unless a narrower layer overrides.
func (s *OIDCClaimsService) SetOrgDefault(orgID int, key, value string) error {
	if err := ValidateClaimKey(key); err != nil {
		return err
	}
	if len(value) > 4096 {
		return errors.New("claim value must be 4096 bytes or fewer")
	}
	_, err := s.db.Exec(`INSERT INTO organization_oidc_claim_defaults (organization_id, claim_key, claim_value)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE claim_value = VALUES(claim_value)`,
		orgID, key, value)
	return err
}

// DeleteOrgDefault removes an org-level default claim. No-op if not set.
func (s *OIDCClaimsService) DeleteOrgDefault(orgID int, key string) error {
	_, err := s.db.Exec(`DELETE FROM organization_oidc_claim_defaults WHERE organization_id=? AND claim_key=?`, orgID, key)
	return err
}

// ListOrgDefaults returns every org-level default claim for the organisation.
func (s *OIDCClaimsService) ListOrgDefaults(orgID int) ([]OIDCClaim, error) {
	return s.queryClaims(`SELECT claim_key, claim_value, updated_at
		FROM organization_oidc_claim_defaults WHERE organization_id=? ORDER BY claim_key`, orgID)
}

// SetProjectDefault upserts a project-level default claim. Applies to every
// token bound to this project (any user) unless a per-user layer overrides.
func (s *OIDCClaimsService) SetProjectDefault(projectID int, key, value string) error {
	if err := ValidateClaimKey(key); err != nil {
		return err
	}
	if len(value) > 4096 {
		return errors.New("claim value must be 4096 bytes or fewer")
	}
	_, err := s.db.Exec(`INSERT INTO project_oidc_claim_defaults (project_id, claim_key, claim_value)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE claim_value = VALUES(claim_value)`,
		projectID, key, value)
	return err
}

// DeleteProjectDefault removes a project-level default claim. No-op if not set.
func (s *OIDCClaimsService) DeleteProjectDefault(projectID int, key string) error {
	_, err := s.db.Exec(`DELETE FROM project_oidc_claim_defaults WHERE project_id=? AND claim_key=?`, projectID, key)
	return err
}

// ListProjectDefaults returns every project-level default claim.
func (s *OIDCClaimsService) ListProjectDefaults(projectID int) ([]OIDCClaim, error) {
	return s.queryClaims(`SELECT claim_key, claim_value, updated_at
		FROM project_oidc_claim_defaults WHERE project_id=? ORDER BY claim_key`, projectID)
}

// MergedClaims returns the effective claim set for tokens issued to userID in
// the context of projectID. Layers are merged broadest→narrowest so the
// narrower layer overrides a same-keyed value from a wider one:
//
//  1. org defaults  2. project defaults  3. user-level  4. user × project
//
// projectID may be 0 to skip the project-bound layers. Values are decoded
// into typed shapes so JSON booleans / numbers / arrays round-trip correctly
// into the JWT.
func (s *OIDCClaimsService) MergedClaims(userID, projectID int) (map[string]interface{}, error) {
	out := map[string]interface{}{}

	// Resolve the user's organisation once so we can pull org defaults. We
	// silently skip the org layer if the lookup fails — the user may have
	// been deleted between the token mint and the claim resolution, and we
	// must not let claim merging fail an otherwise valid login.
	var orgID int
	if err := s.db.QueryRow(`SELECT organization_id FROM users WHERE id=?`, userID).Scan(&orgID); err == nil && orgID > 0 {
		orgDefaults, err := s.ListOrgDefaults(orgID)
		if err != nil {
			return nil, err
		}
		for _, c := range orgDefaults {
			out[c.Key] = decodeClaimValue(c.Value)
		}
	}

	if projectID > 0 {
		projectDefaults, err := s.ListProjectDefaults(projectID)
		if err != nil {
			return nil, err
		}
		for _, c := range projectDefaults {
			out[c.Key] = decodeClaimValue(c.Value)
		}
	}

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

// Claim source identifiers used by MergedClaimsWithSources to attribute each
// effective claim to the layer that produced it. The order mirrors the merge
// precedence (broadest first) so callers can sort by precedence cleanly.
const (
	ClaimSourceOrgDefault     = "org_default"
	ClaimSourceProjectDefault = "project_default"
	ClaimSourceUser           = "user"
	ClaimSourceUserProject    = "user_project"
)

// MergedClaimsWithSources behaves like MergedClaims but also returns a map of
// claim_key → source identifier (see Claim source* constants) so an admin can
// see exactly which layer produced each effective value. The source map only
// records the *winning* layer per key — that's what the token actually carries.
func (s *OIDCClaimsService) MergedClaimsWithSources(userID, projectID int) (map[string]interface{}, map[string]string, error) {
	out := map[string]interface{}{}
	src := map[string]string{}

	var orgID int
	if err := s.db.QueryRow(`SELECT organization_id FROM users WHERE id=?`, userID).Scan(&orgID); err == nil && orgID > 0 {
		orgDefaults, err := s.ListOrgDefaults(orgID)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range orgDefaults {
			out[c.Key] = decodeClaimValue(c.Value)
			src[c.Key] = ClaimSourceOrgDefault
		}
	}

	if projectID > 0 {
		projectDefaults, err := s.ListProjectDefaults(projectID)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range projectDefaults {
			out[c.Key] = decodeClaimValue(c.Value)
			src[c.Key] = ClaimSourceProjectDefault
		}
	}

	userClaims, err := s.ListUserClaims(userID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range userClaims {
		out[c.Key] = decodeClaimValue(c.Value)
		src[c.Key] = ClaimSourceUser
	}

	if projectID > 0 {
		projectClaims, err := s.ListProjectClaims(userID, projectID)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range projectClaims {
			out[c.Key] = decodeClaimValue(c.Value)
			src[c.Key] = ClaimSourceUserProject
		}
	}

	return out, src, nil
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
