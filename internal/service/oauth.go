package service

import (
	"database/sql"
	"encoding/json"

	"blackwall/internal/config"
	"blackwall/internal/security"
)

type OAuthService struct {
	db         *sql.DB
	jwtManager *JWTManager
	claims     *OIDCClaimsService
}

func NewOAuthService(db *sql.DB) *OAuthService {
	return &OAuthService{
		db:         db,
		jwtManager: NewJWTManager(db),
	}
}

// SetClaimsProvider attaches the custom-claims service. Optional — when nil,
// no custom claims are merged into issued tokens. Wired by main.go after
// both services exist so we avoid a constructor-cycle.
func (s *OAuthService) SetClaimsProvider(c *OIDCClaimsService) {
	s.claims = c
}

// ClaimsForUser returns the merged custom claim set for the given user/project.
// projectID may be 0 to fetch only user-level claims. Returns nil safely if
// the claims provider isn't wired (in which case no extra claims are emitted).
func (s *OAuthService) ClaimsForUser(userID, projectID int) map[string]interface{} {
	if s.claims == nil {
		return nil
	}
	out, err := s.claims.MergedClaims(userID, projectID)
	if err != nil {
		return nil
	}
	return out
}

func (s *OAuthService) CreateAuthorizationCode(clientID, userID, projectID int, redirectURI string, scopes []string, codeChallenge, codeChallengeMethod, nonce string) (string, error) {
	code := security.GenerateBase64URLToken(32)
	codeHash := security.HashToken(code)

	scopesJSON, _ := json.Marshal(scopes)
	_, err := s.db.Exec(`INSERT INTO oauth_auth_codes
		(code_hash, client_id, user_id, project_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))`,
		codeHash, clientID, userID, projectID, redirectURI, scopesJSON,
		codeChallenge, codeChallengeMethod, nullStringVal(nonce))
	if err != nil {
		return "", err
	}
	return code, nil
}

func (s *OAuthService) ExchangeAuthorizationCode(code, clientPublicID, redirectURI, codeVerifier string) (map[string]interface{}, error) {
	codeHash := security.HashToken(code)

	var (
		id, clientID, userID, projectID           int
		storedRedirectURI, codeChallenge          string
		codeChallengeMethod                       string
		scopesJSON                                string
		nonce                                     sql.NullString
		accessTokenType                           string
		accessTokenLifetime, refreshTokenLifetime int
		oidcEnabled                               bool
	)

	err := s.db.QueryRow(`SELECT ac.id, ac.client_id, ac.user_id, ac.project_id, ac.redirect_uri,
		ac.scopes, ac.code_challenge, ac.code_challenge_method, ac.nonce, ac.expires_at,
		c.access_token_type, c.access_token_lifetime, c.refresh_token_lifetime, c.oidc_enabled
		FROM oauth_auth_codes ac
		JOIN oauth_clients c ON c.id = ac.client_id
		WHERE ac.code_hash = ? AND c.client_id = ? AND c.status = 'active' AND ac.used_at IS NULL AND ac.expires_at > NOW()`,
		codeHash, clientPublicID).Scan(
		&id, &clientID, &userID, &projectID, &storedRedirectURI,
		&scopesJSON, &codeChallenge, &codeChallengeMethod, &nonce, new(sql.NullTime),
		&accessTokenType, &accessTokenLifetime, &refreshTokenLifetime, &oidcEnabled,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if storedRedirectURI != redirectURI {
		return nil, nil
	}
	if !security.ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod) {
		return nil, nil
	}

	// Mark code as used (single-use enforcement)
	result, err := s.db.Exec(`UPDATE oauth_auth_codes SET used_at = NOW() WHERE id = ? AND used_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return nil, nil
	}

	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)

	// Get role
	var privilegeLevel int
	err = s.db.QueryRow(`SELECT privilege_level FROM user_project_roles WHERE user_id=? AND project_id=?`, userID, projectID).Scan(&privilegeLevel)
	if err != nil {
		return nil, nil
	}

	var privilegeName string
	s.db.QueryRow(`SELECT name FROM project_privilege_levels WHERE project_id=? AND level=?`, projectID, privilegeLevel).Scan(&privilegeName)

	return s.issueTokens(clientID, userID, projectID, scopes, privilegeLevel, ResolvePrivilegeLabel(privilegeLevel, privilegeName),
		accessTokenType, accessTokenLifetime, refreshTokenLifetime, nonce.String, oidcEnabled)
}

func (s *OAuthService) ExchangeRefreshToken(refreshToken, clientPublicID string) (map[string]interface{}, error) {
	tokenHash := security.HashToken(refreshToken)

	var (
		id, clientID, userID, projectID           int
		scopesJSON, clientScopes                  string
		clientStatus                              string
		revokedAt                                 sql.NullTime
		accessTokenType                           string
		accessTokenLifetime, refreshTokenLifetime int
		oidcEnabled                               bool
	)

	err := s.db.QueryRow(`SELECT rt.id, rt.client_id, rt.user_id, rt.project_id,
		rt.scopes, rt.revoked_at, rt.expires_at,
		c.access_token_type, c.access_token_lifetime, c.refresh_token_lifetime,
		c.oidc_enabled, c.scopes AS client_scopes, c.status AS client_status
		FROM oauth_refresh_tokens rt
		JOIN oauth_clients c ON c.id = rt.client_id
		WHERE rt.token_hash = ? AND c.client_id = ? AND rt.expires_at > NOW() LIMIT 1`,
		tokenHash, clientPublicID).Scan(
		&id, &clientID, &userID, &projectID,
		&scopesJSON, &revokedAt, new(sql.NullTime),
		&accessTokenType, &accessTokenLifetime, &refreshTokenLifetime,
		&oidcEnabled, &clientScopes, &clientStatus,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if clientStatus != "active" {
		return nil, nil
	}

	if revokedAt.Valid {
		// Replay detected — revoke token family
		s.revokeTokenFamily(clientID, userID, projectID)
		return nil, nil
	}

	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	result, err := tx.Exec(`UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE id=? AND revoked_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		s.revokeTokenFamily(clientID, userID, projectID)
		return nil, nil
	}

	var privilegeLevel int
	if err = tx.QueryRow(`SELECT privilege_level FROM user_project_roles WHERE user_id=? AND project_id=?`, userID, projectID).Scan(&privilegeLevel); err != nil {
		return nil, nil
	}
	var privilegeName string
	tx.QueryRow(`SELECT name FROM project_privilege_levels WHERE project_id=? AND level=?`, projectID, privilegeLevel).Scan(&privilegeName)

	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)

	tokens, err := s.issueTokensTx(tx, clientID, userID, projectID, scopes, privilegeLevel, ResolvePrivilegeLabel(privilegeLevel, privilegeName),
		accessTokenType, accessTokenLifetime, refreshTokenLifetime, "", oidcEnabled)
	if err != nil {
		return nil, err
	}

	return tokens, tx.Commit()
}

func (s *OAuthService) issueTokens(clientID, userID, projectID int, scopes []string, privilegeLevel int, privilegeName, tokenType string, accessLifetime, refreshLifetime int, nonce string, oidcEnabled bool) (map[string]interface{}, error) {
	return s.issueTokensTx(s.db, clientID, userID, projectID, scopes, privilegeLevel, privilegeName, tokenType, accessLifetime, refreshLifetime, nonce, oidcEnabled)
}

type dbExecer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

func (s *OAuthService) issueTokensTx(db dbExecer, clientID, userID, projectID int, scopes []string, privilegeLevel int, privilegeName, tokenType string, accessLifetime, refreshLifetime int, nonce string, oidcEnabled bool) (map[string]interface{}, error) {
	var userUUID, userLabel string
	if err := s.db.QueryRow(`SELECT uuid, display_label FROM users WHERE id=? AND status='active'`, userID).Scan(&userUUID, &userLabel); err != nil {
		return nil, nil
	}
	var projectUUID string
	if err := s.db.QueryRow(`SELECT uuid FROM projects WHERE id=? AND status='active'`, projectID).Scan(&projectUUID); err != nil {
		return nil, nil
	}
	var clientPublicID string
	if err := s.db.QueryRow(`SELECT client_id FROM oauth_clients WHERE id=? AND status='active'`, clientID).Scan(&clientPublicID); err != nil {
		return nil, nil
	}

	scopeStr := joinScopes(scopes)
	response := map[string]interface{}{
		"token_type": "Bearer",
		"expires_in": accessLifetime,
		"scope":      scopeStr,
	}

	scopesJSON, _ := json.Marshal(scopes)

	var accessToken string
	if tokenType == "jwt" {
		var err error
		accessToken, err = s.jwtManager.CreateAccessToken(userUUID, clientPublicID, scopeStr, projectUUID, privilegeLevel, privilegeName, accessLifetime, nonce)
		if err != nil {
			return nil, err
		}
	} else {
		accessToken = security.GenerateToken(32)
	}

	tokenHash := security.HashToken(accessToken)
	_, err := db.Exec(`INSERT INTO oauth_access_tokens (token_hash, client_id, user_id, project_id, scopes, privilege_level, expires_at) VALUES (?,?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? SECOND))`,
		tokenHash, clientID, userID, projectID, scopesJSON, privilegeLevel, accessLifetime)
	if err != nil {
		return nil, err
	}
	response["access_token"] = accessToken

	// Refresh token
	if containsScope(scopes, "offline_access") {
		rt := security.GenerateToken(32)
		rtHash := security.HashToken(rt)
		_, err = db.Exec(`INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, project_id, scopes, privilege_level, expires_at) VALUES (?,?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? SECOND))`,
			rtHash, clientID, userID, projectID, scopesJSON, privilegeLevel, refreshLifetime)
		if err != nil {
			return nil, err
		}
		response["refresh_token"] = rt
	}

	// ID token — emitted whenever the openid scope is in play, regardless of
	// the per-client oidc_enabled flag. (oidc_enabled was only intended to
	// gate whether a client may *request* OIDC, which is enforced at scope
	// allow-list time. Once openid is in the granted scopes, the spec
	// requires we issue an ID token.)
	if containsScope(scopes, "openid") {
		idClaims := struct{ email, name string }{}
		if containsScope(scopes, "email") && isEmail(userLabel) {
			idClaims.email = userLabel
		}
		if containsScope(scopes, "profile") {
			idClaims.name = userLabel
		}

		// Custom claims: user-level overlaid with project-scoped values.
		// Service is optional — when absent, no extra claims are merged.
		var extra map[string]interface{}
		if s.claims != nil {
			if merged, err := s.claims.MergedClaims(userID, projectID); err == nil {
				extra = merged
			}
		}

		// auth_time is best-effort — we don't track the explicit moment of
		// authentication separately from when this code was issued, so omit
		// it. OIDC §2 says auth_time is REQUIRED only if max_age was
		// requested or essential by client config (we don't support either).
		idToken, err := s.jwtManager.CreateIDToken(userUUID, clientPublicID, nonce, idClaims.email, idClaims.name, accessToken, 0, extra)
		if err == nil {
			response["id_token"] = idToken
		}
	}

	return response, nil
}

func (s *OAuthService) IntrospectToken(token string, requestingClientID int) (map[string]interface{}, error) {
	tokenHash := security.HashToken(token)

	query := `SELECT t.id, t.client_id, t.user_id, t.project_id, t.scopes, t.privilege_level, t.expires_at,
		u.uuid, p.uuid, c.client_id,
		COALESCE(pl.name, '')
		FROM oauth_access_tokens t
		JOIN users u ON u.id=t.user_id
		JOIN projects p ON p.id=t.project_id
		JOIN oauth_clients c ON c.id=t.client_id
		LEFT JOIN project_privilege_levels pl ON pl.project_id=t.project_id AND pl.level=t.privilege_level
		WHERE t.token_hash=? AND t.revoked_at IS NULL AND u.status='active' AND p.status='active' AND c.status='active'`
	args := []interface{}{tokenHash}
	if requestingClientID > 0 {
		query += " AND t.client_id=?"
		args = append(args, requestingClientID)
	}

	var id, cid, uid, pid, pl int
	var scopesJSON, userUUID, projectUUID, clientPublicID, privilegeName string
	var expiresAt sql.NullTime

	query += " AND t.expires_at > NOW()"

	err := s.db.QueryRow(query, args...).Scan(&id, &cid, &uid, &pid, &scopesJSON, &pl, &expiresAt, &userUUID, &projectUUID, &clientPublicID, &privilegeName)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}

	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)

	return map[string]interface{}{
		"active":          true,
		"scope":           joinScopes(scopes),
		"client_id":       clientPublicID,
		"token_type":      "Bearer",
		"exp":             expiresAt.Time.Unix(),
		"sub":             userUUID,
		"aud":             clientPublicID,
		"iss":             config.Get().AppURL,
		"project_id":      projectUUID,
		"privilege_level": pl,
		"privilege_name":  ResolvePrivilegeLabel(pl, privilegeName),
	}, nil
}

func (s *OAuthService) RevokeToken(token string, clientID int) {
	tokenHash := security.HashToken(token)
	q := `UPDATE oauth_access_tokens SET revoked_at=NOW() WHERE token_hash=?`
	args := []interface{}{tokenHash}
	if clientID > 0 {
		q += " AND client_id=?"
		args = append(args, clientID)
	}
	s.db.Exec(q, args...)

	q = `UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE token_hash=?`
	args = []interface{}{tokenHash}
	if clientID > 0 {
		q += " AND client_id=?"
		args = append(args, clientID)
	}
	s.db.Exec(q, args...)
}

func (s *OAuthService) revokeTokenFamily(clientID, userID, projectID int) {
	s.db.Exec(`UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE client_id=? AND user_id=? AND project_id=? AND revoked_at IS NULL`, clientID, userID, projectID)
	s.db.Exec(`UPDATE oauth_access_tokens SET revoked_at=NOW() WHERE client_id=? AND user_id=? AND project_id=? AND revoked_at IS NULL`, clientID, userID, projectID)
}

func containsScope(scopes []string, s string) bool {
	for _, v := range scopes {
		if v == s {
			return true
		}
	}
	return false
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

func isEmail(s string) bool {
	at := false
	for _, c := range s {
		if c == '@' {
			at = true
		}
	}
	return at && len(s) > 3
}

func nullStringVal(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
