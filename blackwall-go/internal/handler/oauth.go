package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"blackwall/internal/config"
	"blackwall/internal/model"
	"blackwall/internal/repository"
	"blackwall/internal/security"
	"blackwall/internal/service"
	tmpl "blackwall/internal/templates"
)

type OAuthHandler struct {
	app         *App
	clientRepo  *repository.OAuthClientRepository
	projectRepo *repository.ProjectRepository
	orgRepo     *repository.OrganizationRepository
	roleRepo    *repository.UserProjectRoleRepository
	privRepo    *repository.PrivilegeLevelRepository
	db          *sql.DB
}

func NewOAuthHandler(app *App, db *sql.DB) *OAuthHandler {
	return &OAuthHandler{
		app:         app,
		clientRepo:  repository.NewOAuthClientRepository(db),
		projectRepo: repository.NewProjectRepository(db),
		orgRepo:     repository.NewOrganizationRepository(db),
		roleRepo:    repository.NewUserProjectRoleRepository(db),
		privRepo:    repository.NewPrivilegeLevelRepository(db),
		db:          db,
	}
}

func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	issuer := config.Get().AppURL
	data := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"jwks_uri":                              issuer + "/oauth/jwks",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"introspection_endpoint":                issuer + "/oauth/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	if audit := getAudit(r); audit != nil {
		audit.LogInfo("oidc.discovery")
	}
	jsonOK(w, data)
}

func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	if audit := getAudit(r); audit != nil {
		audit.LogInfo("jwks.fetch")
	}
	jsonOK(w, h.app.JWT.GetJWKS())
}

func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	audit := getAudit(r)

	if !h.app.RateLimit.Check("ip:"+ip, "oauth.authorize", 120, 60) {
		if audit != nil {
			audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "oauth.authorize"})
		}
		jsonError(w, "too_many_requests", 429)
		return
	}

	params := r.URL.Query()
	clientID := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")

	if clientID == "" || redirectURI == "" {
		if audit != nil {
			audit.LogFail("oauth.authorize.fail", service.AuditMeta{"message": "Missing client_id or redirect_uri"})
		}
		oauthErrJSON(w, "invalid_request", "Missing client_id or redirect_uri")
		return
	}

	client, _ := h.clientRepo.FindByClientID(clientID)
	if client == nil || !client.IsActive() {
		oauthErrJSON(w, "invalid_client", "")
		return
	}
	if !client.HasRedirectURI(redirectURI) {
		oauthErrJSON(w, "invalid_request", "Invalid redirect_uri")
		return
	}

	project, _ := h.projectRepo.FindByID(client.ProjectID)
	if project == nil || !project.IsActive() {
		redirectOAuthErr(w, r, redirectURI, "invalid_request", "Client project invalid", params.Get("state"))
		return
	}

	requestedScopes := splitScopes(params.Get("scope"))
	isOIDC := containsStr(requestedScopes, "openid")

	if ok, errCode, errDesc := security.ValidateOAuthRequest(params, isOIDC); !ok {
		redirectOAuthErr(w, r, redirectURI, errCode, errDesc, params.Get("state"))
		return
	}
	if first := security.FirstDisallowedScope(requestedScopes, client.Scopes); first != "" {
		redirectOAuthErr(w, r, redirectURI, "invalid_scope", "Scope not allowed", params.Get("state"))
		return
	}

	sess, _ := security.GetSession(w, r)
	sess.Set("oauth_auth_request", urlValuesToMap(params))
	sess.Save()

	userID := sess.GetInt("user_id")
	if userID > 0 && !h.isActiveUser(userID) {
		sess.Delete("user_id")
		userID = 0
		sess.Save()
	}

	if userID == 0 {
		org, _ := h.orgRepo.FindByID(project.OrganizationID)
		csrfToken, _ := security.GenerateCSRFToken(w, r)
		tmpl.Standalone(w, "oauth/login.html", map[string]interface{}{
			"ClientName":   client.Name,
			"ReturnURL":    redirectURI,
			"Organization": org,
			"CSRFToken":    csrfToken,
		})
		return
	}

	role, _ := h.roleRepo.FindByUserAndProject(userID, project.ID)
	if role == nil {
		redirectOAuthErr(w, r, redirectURI, "access_denied", "User not authorized for this project", params.Get("state"))
		return
	}

	pl, _ := h.privRepo.FindByProjectAndLevel(project.ID, role.PrivilegeLevel)
	privilegeLabel := service.ResolvePrivilegeLabel(role.PrivilegeLevel, "")
	if pl != nil {
		privilegeLabel = service.ResolvePrivilegeLabel(role.PrivilegeLevel, pl.Name)
	}

	if audit != nil {
		audit.LogInfo("oauth.authorize.begin", service.AuditMeta{
			"actor_user_id":          userID,
			"project_id":             project.ID,
			"oauth_client_id":        client.ID,
			"oauth_client_public_id": client.ClientID,
		})
	}

	csrfToken, _ := security.GenerateCSRFToken(w, r)
	tmpl.Standalone(w, "oauth/consent.html", map[string]interface{}{
		"Client":               client,
		"Project":              project,
		"Scopes":               requestedScopes,
		"PrivilegeLevel":       pl,
		"PrivilegeLabel":       privilegeLabel,
		"PrivilegeLevelNumber": role.PrivilegeLevel,
		"CSRFToken":            csrfToken,
		"Params":               urlValuesToMap(params),
	})
}

func (h *OAuthHandler) AuthorizePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	audit := getAudit(r)

	if !security.ValidateCSRFToken(w, r, r.FormValue("csrf_token")) {
		if audit != nil {
			audit.LogFail("security.csrf.fail", service.AuditMeta{"message": "CSRF validation failed"})
		}
		oauthErrJSON(w, "invalid_request", "CSRF validation failed")
		return
	}

	sess, _ := security.GetSession(w, r)
	paramsMap, _ := sess.Get("oauth_auth_request").(map[string]string)
	if paramsMap == nil {
		paramsMap = map[string]string{}
		for k, v := range r.Form {
			if strings.HasPrefix(k, "auth_request[") && len(v) > 0 {
				key := strings.TrimSuffix(strings.TrimPrefix(k, "auth_request["), "]")
				paramsMap[key] = v[0]
			}
		}
	}
	if len(paramsMap) == 0 {
		oauthErrJSON(w, "invalid_request", "No authorization request found")
		return
	}

	redirectURI := paramsMap["redirect_uri"]
	clientPublicID := paramsMap["client_id"]
	userID := sess.GetInt("user_id")

	if userID == 0 {
		http.Redirect(w, r, "/admin/login", 302)
		return
	}
	if !h.isActiveUser(userID) {
		sess.Delete("user_id")
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, "access_denied", "User account inactive", paramsMap["state"])
		return
	}

	client, _ := h.clientRepo.FindByClientID(clientPublicID)
	if client == nil || !client.IsActive() || !client.HasRedirectURI(redirectURI) {
		sess.Delete("oauth_auth_request")
		sess.Save()
		oauthErrJSON(w, "invalid_client", "")
		return
	}

	project, _ := h.projectRepo.FindByID(client.ProjectID)
	if project == nil || !project.IsActive() {
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, "invalid_request", "Client project invalid", paramsMap["state"])
		return
	}

	if r.FormValue("deny") != "" {
		if audit != nil {
			audit.LogInfo("oauth.authorize.deny", service.AuditMeta{"actor_user_id": userID, "project_id": project.ID})
		}
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, "access_denied", "", paramsMap["state"])
		return
	}

	requestedScopes := splitScopes(paramsMap["scope"])
	isOIDC := containsStr(requestedScopes, "openid")

	params := mapToURLValues(paramsMap)
	if ok, errCode, errDesc := security.ValidateOAuthRequest(params, isOIDC); !ok {
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, errCode, errDesc, paramsMap["state"])
		return
	}

	if first := security.FirstDisallowedScope(requestedScopes, client.Scopes); first != "" {
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, "invalid_scope", "Scope not allowed", paramsMap["state"])
		return
	}

	role, _ := h.roleRepo.FindByUserAndProject(userID, project.ID)
	if role == nil {
		sess.Delete("oauth_auth_request")
		sess.Save()
		redirectOAuthErr(w, r, redirectURI, "access_denied", "User not authorized", paramsMap["state"])
		return
	}

	// OIDC nonce replay guard — checked server-side against the DB so it
	// works across sessions, not just within the same browser session.
	if isOIDC {
		nonce := paramsMap["nonce"]
		if nonce == "" {
			sess.Delete("oauth_auth_request")
			sess.Save()
			redirectOAuthErr(w, r, redirectURI, "invalid_request", "Nonce required", paramsMap["state"])
			return
		}
		var nonceExists int
		h.db.QueryRow(
			`SELECT COUNT(*) FROM oauth_auth_codes WHERE client_id=? AND nonce=?`,
			client.ID, nonce,
		).Scan(&nonceExists)
		if nonceExists > 0 {
			if audit != nil {
				audit.LogFail("oauth.authorize.fail", service.AuditMeta{
					"message":                "Nonce replay detected",
					"error_code":             "invalid_request",
					"actor_user_id":          userID,
					"oauth_client_id":        client.ID,
					"oauth_client_public_id": client.ClientID,
				})
			}
			sess.Delete("oauth_auth_request")
			sess.Save()
			redirectOAuthErr(w, r, redirectURI, "invalid_request", "Nonce replay detected", paramsMap["state"])
			return
		}
	}

	code, err := h.app.OAuth.CreateAuthorizationCode(
		client.ID, userID, project.ID, redirectURI,
		requestedScopes, paramsMap["code_challenge"], paramsMap["code_challenge_method"], paramsMap["nonce"],
	)
	if err != nil {
		redirectOAuthErr(w, r, redirectURI, "server_error", "", paramsMap["state"])
		return
	}

	if audit != nil {
		pl, _ := h.privRepo.FindByProjectAndLevel(project.ID, role.PrivilegeLevel)
		pName := ""
		if pl != nil {
			pName = pl.Name
		}
		audit.LogSuccess("oauth.authorize.approve", service.AuditMeta{
			"actor_user_id":          userID,
			"project_id":             project.ID,
			"oauth_client_id":        client.ID,
			"oauth_client_public_id": client.ClientID,
			"privilege_level":        role.PrivilegeLevel,
			"privilege_name":         service.ResolvePrivilegeLabel(role.PrivilegeLevel, pName),
		})
	}

	sess.Delete("oauth_auth_request")
	sess.Save()

	callbackURL := redirectURI + "?code=" + url.QueryEscape(code)
	if state := paramsMap["state"]; state != "" {
		callbackURL += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, callbackURL, 302)
}

func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	audit := getAudit(r)
	ip := getIP(r)
	if !h.app.RateLimit.Check("ip:"+ip, "oauth.token", 60, 60) {
		if audit != nil {
			audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "oauth.token"})
		}
		jsonError(w, "too_many_requests", 429)
		return
	}

	r.ParseForm()
	body := formToMap(r.Form)
	grantType := body["grant_type"]
	if grantType == "" {
		jsonError(w, "invalid_request", 400)
		return
	}

	client, errCode := authenticateClient(r, body, h.clientRepo)
	if client == nil {
		status := 401
		if errCode == "unauthorized_client" {
			status = 400
		}
		jsonError(w, errCode, status)
		return
	}

	if !client.SupportsGrant(grantType) {
		jsonError(w, "unauthorized_client", 400)
		return
	}

	switch grantType {
	case "authorization_code":
		code := body["code"]
		redirectURI := body["redirect_uri"]
		codeVerifier := body["code_verifier"]
		if code == "" || redirectURI == "" || codeVerifier == "" {
			jsonError(w, "invalid_request", 400)
			return
		}
		tokens, err := h.app.OAuth.ExchangeAuthorizationCode(code, client.ClientID, redirectURI, codeVerifier)
		if err != nil || tokens == nil {
			if audit != nil {
				audit.LogFail("oauth.token.fail", service.AuditMeta{"error_code": "invalid_grant", "oauth_client_public_id": client.ClientID})
			}
			jsonError(w, "invalid_grant", 400)
			return
		}
		if audit != nil {
			audit.LogSuccess("oauth.token.issue", service.AuditMeta{"oauth_client_public_id": client.ClientID, "grant_type": "authorization_code"})
		}
		jsonOK(w, tokens)

	case "refresh_token":
		rt := body["refresh_token"]
		if rt == "" {
			jsonError(w, "invalid_request", 400)
			return
		}
		tokens, err := h.app.OAuth.ExchangeRefreshToken(rt, client.ClientID)
		if err != nil || tokens == nil {
			if audit != nil {
				audit.LogFail("oauth.token.fail", service.AuditMeta{"error_code": "invalid_grant", "oauth_client_public_id": client.ClientID})
			}
			jsonError(w, "invalid_grant", 400)
			return
		}
		if audit != nil {
			audit.LogSuccess("oauth.token.issue", service.AuditMeta{"oauth_client_public_id": client.ClientID, "grant_type": "refresh_token"})
		}
		jsonOK(w, tokens)

	default:
		jsonError(w, "unsupported_grant_type", 400)
	}
}

func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.ParseForm()
	body := formToMap(r.Form)
	ip := getIP(r)
	if !h.app.RateLimit.Check("ip:"+ip, "oauth.revoke", 60, 60) {
		jsonError(w, "too_many_requests", 429)
		return
	}
	if body["token"] == "" {
		jsonError(w, "invalid_request", 400)
		return
	}
	client, errCode := authenticateClient(r, body, h.clientRepo)
	if client == nil {
		status := 401
		if errCode == "unauthorized_client" {
			status = 400
		}
		jsonError(w, errCode, status)
		return
	}
	if !client.IsConfidential() {
		jsonError(w, "unauthorized_client", 400)
		return
	}
	h.app.OAuth.RevokeToken(body["token"], client.ID)
	if audit := getAudit(r); audit != nil {
		audit.LogSuccess("oauth.token.revoke", service.AuditMeta{"oauth_client_public_id": client.ClientID})
	}
	w.WriteHeader(200)
}

func (h *OAuthHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.ParseForm()
	body := formToMap(r.Form)
	ip := getIP(r)
	if !h.app.RateLimit.Check("ip:"+ip, "oauth.introspect", 60, 60) {
		jsonOK(w, map[string]bool{"active": false})
		return
	}
	client, errCode := authenticateClient(r, body, h.clientRepo)
	if client == nil {
		status := 401
		if errCode == "unauthorized_client" {
			status = 400
		}
		jsonError(w, errCode, status)
		return
	}
	if !client.IsConfidential() {
		jsonOK(w, map[string]bool{"active": false})
		return
	}
	if body["token"] == "" {
		jsonOK(w, map[string]bool{"active": false})
		return
	}
	result, _ := h.app.OAuth.IntrospectToken(body["token"], client.ID)
	if audit := getAudit(r); audit != nil {
		audit.LogInfo("oauth.token.introspect", service.AuditMeta{"oauth_client_public_id": client.ClientID})
	}
	jsonOK(w, result)
}

func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := getIP(r)
	audit := getAudit(r)

	if !h.app.RateLimit.Check("ip:"+ip, "oauth.userinfo", 120, 60) {
		jsonError(w, "too_many_requests", 429)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="blackwall"`)
		jsonError(w, "invalid_token", 401)
		return
	}
	accessToken := authHeader[7:]

	// Try JWT
	parsed, _ := h.app.JWT.ParseAndValidate(accessToken)
	if parsed != nil && parsed.Valid {
		sub, _ := parsed.Claims["sub"].(string)
		scopeStr, _ := parsed.Claims["scope"].(string)
		scopes := splitScopes(scopeStr)

		if !containsStr(scopes, "openid") {
			if audit != nil {
				audit.LogFail("oidc.userinfo.fail", service.AuditMeta{"failure_reason": "Missing openid scope"})
			}
			jsonError(w, "insufficient_scope", 403)
			return
		}

		// OIDC Core §5.3.2: the access token MUST be the one issued for the
		// userinfo endpoint of a specific client. We extract the audience
		// claim and require both that an active client owns it AND that the
		// stored token row is bound to that same client.
		audience := extractAudience(parsed.Claims["aud"])
		if audience == "" {
			if audit != nil {
				audit.LogFail("oidc.userinfo.fail", service.AuditMeta{"failure_reason": "Missing audience claim"})
			}
			jsonError(w, "invalid_token", 401)
			return
		}
		var clientRowID int
		_ = h.db.QueryRow(`SELECT id FROM oauth_clients WHERE client_id=? AND status='active'`, audience).Scan(&clientRowID)
		if clientRowID == 0 {
			if audit != nil {
				audit.LogFail("oidc.userinfo.fail", service.AuditMeta{"failure_reason": "Audience client invalid", "oauth_client_public_id": audience})
			}
			jsonError(w, "invalid_token", 401)
			return
		}

		tokenHash := security.HashToken(accessToken)
		var exists int
		h.db.QueryRow(
			`SELECT 1 FROM oauth_access_tokens WHERE token_hash=? AND client_id=? AND revoked_at IS NULL AND expires_at > NOW()`,
			tokenHash, clientRowID,
		).Scan(&exists)
		if exists == 0 {
			if audit != nil {
				audit.LogFail("oidc.userinfo.fail", service.AuditMeta{"failure_reason": "Token revoked or expired", "oauth_client_public_id": audience})
			}
			jsonError(w, "invalid_token", 401)
			return
		}

		var userID int
		var userLabel string
		h.db.QueryRow(`SELECT id, display_label FROM users WHERE uuid=? AND status='active'`, sub).Scan(&userID, &userLabel)
		if userID == 0 {
			jsonError(w, "invalid_token", 401)
			return
		}

		// Resolve the internal project_id from the project_id claim (a UUID)
		// so we can merge project-scoped custom claims.
		projectUUID, _ := parsed.Claims["project_id"].(string)
		var projectID int
		if projectUUID != "" {
			h.db.QueryRow(`SELECT id FROM projects WHERE uuid=? AND status='active'`, projectUUID).Scan(&projectID)
		}

		userinfo := map[string]interface{}{"sub": sub}
		if containsStr(scopes, "profile") {
			userinfo["name"] = userLabel
			userinfo["preferred_username"] = userLabel
		}
		if containsStr(scopes, "email") && isEmailAddr(userLabel) {
			userinfo["email"] = userLabel
			userinfo["email_verified"] = true
		}
		// Custom claims merged last so the standard fields above remain
		// authoritative (the service also blocks reserved keys at write time).
		mergeCustomClaims(userinfo, h.app.OAuth.ClaimsForUser(userID, projectID))

		if audit != nil {
			audit.LogSuccess("oidc.userinfo.success", service.AuditMeta{"actor_user_id": userID, "actor_user_uuid": sub, "oauth_client_public_id": audience})
		}
		jsonOK(w, userinfo)
		return
	}

	// Opaque token
	tokenHash := security.HashToken(accessToken)
	var userID, projectID int
	var userUUID, userLabel, scopesJSON string
	err := h.db.QueryRow(`SELECT t.user_id, t.project_id, u.uuid, u.display_label, t.scopes
		FROM oauth_access_tokens t
		JOIN users u ON u.id=t.user_id
		WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>NOW() AND u.status='active'`,
		tokenHash).Scan(&userID, &projectID, &userUUID, &userLabel, &scopesJSON)
	if err != nil {
		jsonError(w, "invalid_token", 401)
		return
	}

	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)
	if !containsStr(scopes, "openid") {
		jsonError(w, "insufficient_scope", 403)
		return
	}

	userinfo := map[string]interface{}{"sub": userUUID}
	if containsStr(scopes, "profile") {
		userinfo["name"] = userLabel
		userinfo["preferred_username"] = userLabel
	}
	if containsStr(scopes, "email") && isEmailAddr(userLabel) {
		userinfo["email"] = userLabel
		userinfo["email_verified"] = true
	}
	mergeCustomClaims(userinfo, h.app.OAuth.ClaimsForUser(userID, projectID))

	if audit != nil {
		audit.LogSuccess("oidc.userinfo.success", service.AuditMeta{"actor_user_id": userID, "actor_user_uuid": userUUID})
	}
	jsonOK(w, userinfo)
}

// mergeCustomClaims overlays src into dst without overriding any standard
// userinfo field (sub, name, preferred_username, email, email_verified).
// This is the runtime safety net behind the write-time reserved-key check.
func mergeCustomClaims(dst map[string]interface{}, src map[string]interface{}) {
	if len(src) == 0 {
		return
	}
	standard := map[string]struct{}{
		"sub": {}, "name": {}, "preferred_username": {},
		"email": {}, "email_verified": {},
	}
	for k, v := range src {
		if _, locked := standard[k]; locked {
			continue
		}
		dst[k] = v
	}
}

func (h *OAuthHandler) LoginChallenge(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !security.ValidateCSRFToken(w, r, r.FormValue("csrf_token")) {
		jsonError(w, "Invalid CSRF token", 403)
		return
	}
	ip := getIP(r)
	if !h.app.RateLimit.Check("ip:"+ip, "webauthn.login.oauth.challenge", 60, 300) {
		jsonError(w, "too_many_requests", 429)
		return
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)
	encoded := base64.StdEncoding.EncodeToString(challenge)

	sess, _ := security.GetSession(w, r)
	sess.Set("oauth_webauthn_challenge", map[string]interface{}{
		"value":      encoded,
		"expires_at": time.Now().Unix() + 120,
	})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]string{
		"challenge":  encoded,
		"csrf_token": nextCSRF,
	})
}

func (h *OAuthHandler) LoginVerify(w http.ResponseWriter, r *http.Request) {
	audit := getAudit(r)
	ip := getIP(r)
	if !h.app.RateLimit.Check("ip:"+ip, "webauthn.login.oauth.verify", 20, 300) {
		jsonError(w, "too_many_requests", 429)
		return
	}

	var body struct {
		CSRFToken string `json:"csrf_token"`
		ID        string `json:"id"`
		Response  struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if !parseJSON(r, &body) {
		jsonError(w, "invalid_request", 400)
		return
	}
	if !security.ValidateCSRFToken(w, r, body.CSRFToken) {
		if audit != nil {
			audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "oauth.login_verify"})
		}
		jsonError(w, "Invalid CSRF token", 403)
		return
	}

	sess, _ := security.GetSession(w, r)
	challengeState, _ := sess.Get("oauth_webauthn_challenge").(map[string]interface{})
	if challengeState == nil {
		jsonError(w, "Session expired", 400)
		return
	}
	expectedChallenge, _ := challengeState["value"].(string)
	expiresAt, _ := challengeState["expires_at"].(int64)
	if expectedChallenge == "" || (expiresAt > 0 && time.Now().Unix() > expiresAt) {
		sess.Delete("oauth_webauthn_challenge")
		sess.Save()
		jsonError(w, "Session expired", 400)
		return
	}

	authRequest := sess.Get("oauth_auth_request")
	sess.Delete("oauth_webauthn_challenge")
	sess.Save()

	if !h.app.WebAuthn.VerifyAssertion(body.ID, body.Response.ClientDataJSON, body.Response.AuthenticatorData, body.Response.Signature, expectedChallenge) {
		if audit != nil {
			audit.LogFail("oauth.login.fail", service.AuditMeta{"failure_reason": "Assertion verification failed"})
		}
		jsonError(w, "Invalid credential", 400)
		return
	}

	cred, _ := h.app.WebAuthn.GetCredentialByID(body.ID)
	if cred == nil {
		jsonError(w, "Invalid credential", 400)
		return
	}

	var status string
	h.db.QueryRow(`SELECT status FROM users WHERE id=?`, cred.UserID).Scan(&status)
	if status != "active" {
		if audit != nil {
			audit.LogFail("oauth.login.fail", service.AuditMeta{"failure_reason": "User inactive", "actor_user_id": cred.UserID})
		}
		jsonError(w, "Invalid credential", 403)
		return
	}

	sess.Set("user_id", cred.UserID)
	if authRequest != nil {
		sess.Set("oauth_auth_request", authRequest)
	}
	sess.RegenerateID()
	sess.Save()

	paramsMap, _ := authRequest.(map[string]string)
	returnURL := "/oauth/authorize?" + mapToURLValues(paramsMap).Encode()

	if audit != nil {
		audit.LogSuccess("oauth.login.success", service.AuditMeta{"actor_user_id": cred.UserID, "webauthn_credential_public_id": body.ID})
	}
	jsonOK(w, map[string]interface{}{"success": true, "redirect": returnURL})
}

func (h *OAuthHandler) isActiveUser(userID int) bool {
	var status string
	h.db.QueryRow(`SELECT status FROM users WHERE id=?`, userID).Scan(&status)
	return status == "active"
}

// authenticateClient wraps security.AuthenticateOAuthClient with repo lookup.
func authenticateClient(r *http.Request, body map[string]string, repo *repository.OAuthClientRepository) (*model.OAuthClient, string) {
	return security.AuthenticateOAuthClient(
		r.Header.Get("Authorization"),
		body,
		func(id string) (*model.OAuthClient, error) {
			return repo.FindByClientID(id)
		},
	)
}

// Package-level helpers
func oauthErrJSON(w http.ResponseWriter, code, desc string) {
	data := map[string]string{"error": code}
	if desc != "" {
		data["error_description"] = desc
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	json.NewEncoder(w).Encode(data)
}

func redirectOAuthErr(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u := redirectURI + "?error=" + url.QueryEscape(code)
	if desc != "" {
		u += "&error_description=" + url.QueryEscape(desc)
	}
	if state != "" {
		u += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, u, 302)
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func formToMap(form url.Values) map[string]string {
	m := map[string]string{}
	for k, v := range form {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

func urlValuesToMap(params url.Values) map[string]string {
	m := map[string]string{}
	for k, v := range params {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

func mapToURLValues(m map[string]string) url.Values {
	v := url.Values{}
	for k, val := range m {
		v.Set(k, val)
	}
	return v
}

func isEmailAddr(s string) bool {
	return strings.Contains(s, "@") && len(s) > 3
}

// extractAudience returns the first string from a JWT `aud` claim, which can
// appear as a single string or a string array per RFC 7519 §4.1.3.
func extractAudience(claim interface{}) string {
	switch v := claim.(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
