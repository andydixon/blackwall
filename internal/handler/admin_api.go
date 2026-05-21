package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/security"
	"blackwall/internal/service"
)

// adminAPICtxKey is the context key holding the resolved admin actor for a
// bearer-authenticated API request.
type adminAPICtxKey struct{}

// AdminAPIActor is the data the API authentication middleware attaches to the
// request context after validating a bearer token. Capabilities are looked up
// fresh from the user's role on each request (no token-side caching), so
// revoking a user's admin role takes effect immediately.
type AdminAPIActor struct {
	UserID     int
	TokenID    int
	TokenScope []string
	AdminRole  string
}

// AdminAPIBearerAuth is router middleware that validates the
// `Authorization: Bearer <bw_admin_*>` header on every request. Rejects
// missing / unknown / revoked / expired tokens with the matching OAuth 2.0
// bearer error code. Successful resolution stashes an AdminAPIActor in the
// context so downstream handlers can call adminAPIActor(r).
func (h *AdminHandler) AdminAPIBearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="blackwall-admin"`)
			jsonAPIError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
			return
		}
		token := strings.TrimSpace(auth[7:])
		t, err := h.App.AdminTokens.Lookup(token)
		if err == sql.ErrNoRows || t == nil {
			jsonAPIError(w, http.StatusUnauthorized, "invalid_token", "token not found")
			return
		}
		if err != nil {
			// Lookup returns named errors for revoked / expired so we
			// surface them precisely rather than collapsing to one code.
			code := err.Error()
			switch code {
			case "revoked":
				jsonAPIError(w, http.StatusUnauthorized, "invalid_token", "token revoked")
				return
			case "expired":
				jsonAPIError(w, http.StatusUnauthorized, "invalid_token", "token expired")
				return
			default:
				jsonAPIError(w, http.StatusInternalServerError, "internal_error", err.Error())
				return
			}
		}
		role, _ := h.App.AdminAuth.GetRole(t.UserID)
		if role == "" {
			jsonAPIError(w, http.StatusForbidden, "no_admin_role", "owning user is not an admin")
			return
		}
		actor := &AdminAPIActor{
			UserID:     t.UserID,
			TokenID:    t.ID,
			TokenScope: t.Scopes,
			AdminRole:  role,
		}
		r = r.WithContext(setAdminAPIActor(r.Context(), actor))
		next.ServeHTTP(w, r)
	})
}

func setAdminAPIActor(ctx context.Context, a *AdminAPIActor) context.Context {
	return context.WithValue(ctx, adminAPICtxKey{}, a)
}

func adminAPIActor(r *http.Request) *AdminAPIActor {
	v, _ := r.Context().Value(adminAPICtxKey{}).(*AdminAPIActor)
	return v
}

// requireAPICapability returns true if the actor's admin role has the named
// capability. Mirrors the cookie-path capability check so JSON consumers
// see the same authorisation surface as the UI.
func (h *AdminHandler) requireAPICapability(w http.ResponseWriter, r *http.Request, cap string) bool {
	a := adminAPIActor(r)
	if a == nil {
		jsonAPIError(w, http.StatusUnauthorized, "invalid_token", "no actor")
		return false
	}
	if !security.HasCapability(a.AdminRole, cap) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "missing capability: "+cap)
		return false
	}
	return true
}

// ─── Resource endpoints ─────────────────────────────────────────────────────

// APIListOrganizations returns every organisation the actor can view.
func (h *AdminHandler) APIListOrganizations(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_organizations") {
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	var rows *sql.Rows
	var err error
	if scope.IsSuperAdmin {
		rows, err = h.DB.Query(`SELECT uuid, name, slug, status FROM organizations ORDER BY name`)
	} else if len(scope.OrganizationIDs) > 0 {
		ph, args := inClausePlaceholders(scope.OrganizationIDs)
		rows, err = h.DB.Query(`SELECT uuid, name, slug, status FROM organizations WHERE id IN (`+ph+`) ORDER BY name`, args...)
	}
	if err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	var out []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var uuid, name, slug, status string
			rows.Scan(&uuid, &name, &slug, &status)
			out = append(out, map[string]interface{}{
				"uuid": uuid, "name": name, "slug": slug, "status": status,
			})
		}
	}
	jsonOK(w, map[string]interface{}{"organizations": out})
}

// APIListProjects returns every project the actor can view, optionally
// filtered by ?org=<uuid>.
func (h *AdminHandler) APIListProjects(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	orgFilter := r.URL.Query().Get("org")

	q := `SELECT p.uuid, p.name, p.status, o.uuid, o.name
		FROM projects p LEFT JOIN organizations o ON o.id = p.organization_id`
	args := []interface{}{}
	conds := []string{}
	if !scope.IsSuperAdmin {
		if len(scope.ProjectIDs) == 0 {
			jsonOK(w, map[string]interface{}{"projects": []interface{}{}})
			return
		}
		ph, ids := inClausePlaceholders(scope.ProjectIDs)
		conds = append(conds, "p.id IN ("+ph+")")
		args = append(args, ids...)
	}
	if orgFilter != "" {
		conds = append(conds, "o.uuid = ?")
		args = append(args, orgFilter)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY p.name"
	rows, err := h.DB.Query(q, args...)
	if err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var puid, pname, pstatus string
		var ouid, oname sql.NullString
		rows.Scan(&puid, &pname, &pstatus, &ouid, &oname)
		out = append(out, map[string]interface{}{
			"uuid": puid, "name": pname, "status": pstatus,
			"organization_uuid": ouid.String, "organization_name": oname.String,
		})
	}
	jsonOK(w, map[string]interface{}{"projects": out})
}

// APIGetProject returns one project's details + its feature flags.
func (h *AdminHandler) APIGetProject(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var id int
	var name, status string
	var orgUUID, orgName sql.NullString
	err := h.DB.QueryRow(`SELECT p.id, p.name, p.status, o.uuid, o.name
		FROM projects p LEFT JOIN organizations o ON o.id=p.organization_id WHERE p.uuid=?`, uuidStr).Scan(&id, &name, &status, &orgUUID, &orgName)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	feats, _ := h.App.Features.Get(id)
	jsonOK(w, map[string]interface{}{
		"uuid": uuidStr, "name": name, "status": status,
		"organization_uuid": orgUUID.String, "organization_name": orgName.String,
		"features": map[string]interface{}{
			"webhooks_enabled":        feats.WebhooksEnabled,
			"db_sessions_enabled":     feats.DBSessionsEnabled,
			"max_concurrent_sessions": feats.MaxConcurrentSessions,
			"custom_branding_enabled": feats.CustomBrandingEnabled,
			"step_up_required":        feats.StepUpRequired,
		},
	})
}

// APIListUsers returns users — optionally filtered by ?org=<uuid>.
func (h *AdminHandler) APIListUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	orgFilter := r.URL.Query().Get("org")
	q := `SELECT u.uuid, u.display_label, u.status, o.uuid FROM users u
		LEFT JOIN organizations o ON o.id=u.organization_id`
	args := []interface{}{}
	conds := []string{}
	if !scope.IsSuperAdmin {
		if len(scope.OrganizationIDs) == 0 {
			jsonOK(w, map[string]interface{}{"users": []interface{}{}})
			return
		}
		ph, ids := inClausePlaceholders(scope.OrganizationIDs)
		conds = append(conds, "u.organization_id IN ("+ph+")")
		args = append(args, ids...)
	}
	if orgFilter != "" {
		conds = append(conds, "o.uuid=?")
		args = append(args, orgFilter)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY u.display_label LIMIT 1000"
	rows, err := h.DB.Query(q, args...)
	if err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var uuid, label, status string
		var orgUUID sql.NullString
		rows.Scan(&uuid, &label, &status, &orgUUID)
		out = append(out, map[string]interface{}{
			"uuid": uuid, "display_label": label, "status": status,
			"organization_uuid": orgUUID.String,
		})
	}
	jsonOK(w, map[string]interface{}{"users": out})
}

// APIListOAuthClients returns the OAuth clients registered under a project.
func (h *AdminHandler) APIListOAuthClients(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	rows, err := h.DB.Query(`SELECT client_id, name, status, oidc_enabled, access_token_type FROM oauth_clients WHERE project_id=? ORDER BY name`, pid)
	if err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var cid, name, status, tokenType string
		var oidc bool
		rows.Scan(&cid, &name, &status, &oidc, &tokenType)
		out = append(out, map[string]interface{}{
			"client_id": cid, "name": name, "status": status,
			"oidc_enabled": oidc, "access_token_type": tokenType,
		})
	}
	jsonOK(w, map[string]interface{}{"oauth_clients": out})
}

// APIListClaimDefaults returns the per-project default claims.
func (h *AdminHandler) APIListClaimDefaults(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	claims, _ := h.App.Claims.ListProjectDefaults(pid)
	out := make([]map[string]interface{}, 0, len(claims))
	for _, c := range claims {
		out = append(out, map[string]interface{}{
			"key":   c.Key,
			"value": c.Value,
		})
	}
	jsonOK(w, map[string]interface{}{"claim_defaults": out})
}

// APIUpsertClaimDefault sets a per-project default claim. JSON body:
//
//	{"key": "preferred_username", "value": "team-grafana"}
func (h *AdminHandler) APIUpsertClaimDefault(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var body struct{ Key, Value string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if err := h.App.Claims.SetProjectDefault(pid, body.Key, body.Value); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_claim", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.claim_default.upsert", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"claim_key":     body.Key,
	})
	w.WriteHeader(http.StatusNoContent)
}

// APIListWebhooks returns webhook endpoints for a project.
func (h *AdminHandler) APIListWebhooks(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	endpoints, _ := h.App.Webhooks.ListForProject(pid)
	out := make([]map[string]interface{}, 0, len(endpoints))
	for _, e := range endpoints {
		out = append(out, map[string]interface{}{
			"public_id":            e.PublicID,
			"target_url":           e.TargetURL,
			"events":               e.Events,
			"status":               e.Status,
			"description":          e.Description,
			"consecutive_failures": e.ConsecutiveFailures,
		})
	}
	jsonOK(w, map[string]interface{}{"webhooks": out})
}

// APIDeleteClaimDefault removes a project-default claim. JSON body OR
// query string: ?key=<claim_key>. Body wins if both are present.
//
// Returns 204 No Content on success; 404 if the project (or any claim with
// that key) is absent — we don't distinguish a missing claim from one that
// was never set, because either outcome leaves the post-state identical.
func (h *AdminHandler) APIDeleteClaimDefault(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		var body struct{ Key string }
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			key = strings.TrimSpace(body.Key)
		}
	}
	if key == "" {
		jsonAPIError(w, http.StatusBadRequest, "missing_key", "claim key required via ?key= or JSON body")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	if err := h.App.Claims.DeleteProjectDefault(pid, key); err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.claim_default.delete", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"claim_key":     key,
	})
	w.WriteHeader(http.StatusNoContent)
}

// APIPatchWebhook updates a webhook endpoint. Any field omitted from the
// body is left untouched. To rotate the secret, send "rotate_secret": true
// and check the returned object for the new value (shown ONCE).
func (h *AdminHandler) APIPatchWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "endpointId")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	// Load the existing row so we know which fields to keep when the body
	// only provides a subset.
	existing, err := h.App.Webhooks.GetEndpoint(publicID)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	var body struct {
		TargetURL    *string  `json:"target_url"`
		Events       []string `json:"events"`
		Description  *string  `json:"description"`
		Status       *string  `json:"status"`
		RotateSecret bool     `json:"rotate_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	target := existing.TargetURL
	if body.TargetURL != nil {
		target = *body.TargetURL
	}
	desc := existing.Description
	if body.Description != nil {
		desc = *body.Description
	}
	events := existing.Events
	if body.Events != nil {
		events = body.Events
	}
	status := existing.Status
	if body.Status != nil {
		status = *body.Status
	}
	ep, err := h.App.Webhooks.UpdateEndpoint(publicID, target, desc, events, status, body.RotateSecret)
	if err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_webhook", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.webhook.update", service.AuditMeta{
		"actor_user_id": a.UserID,
		"target_type":   "webhook_endpoint",
		"target_id":     int64(ep.ID),
	})
	resp := map[string]interface{}{
		"public_id":   ep.PublicID,
		"target_url":  ep.TargetURL,
		"events":      ep.Events,
		"status":      ep.Status,
		"description": ep.Description,
	}
	// Only echo the secret when we rotated it — otherwise honour the
	// "shown once" contract by hiding the existing stored value.
	if body.RotateSecret {
		resp["secret"] = ep.Secret
	}
	jsonOK(w, resp)
}

// APIDeleteWebhook removes a webhook endpoint and all its delivery rows
// (FK cascade). Returns 204 on success.
func (h *AdminHandler) APIDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "endpointId")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	// Confirm the endpoint actually belongs to this project before deleting —
	// a stale publicID from another project shouldn't be wipeable just because
	// the caller has scope on the URL's projectUuid.
	ep, err := h.App.Webhooks.GetEndpoint(publicID)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 || ep.ProjectID != pid {
		jsonAPIError(w, http.StatusNotFound, "not_found", "endpoint not found in this project")
		return
	}
	if err := h.App.Webhooks.DeleteEndpoint(publicID); err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.webhook.delete", service.AuditMeta{
		"actor_user_id": a.UserID,
		"target_type":   "webhook_endpoint",
		"target_id":     int64(ep.ID),
	})
	w.WriteHeader(http.StatusNoContent)
}

// APICreateWebhook registers a new webhook endpoint. JSON body:
//
//	{"target_url": "https://...", "events": ["*"], "description": ""}
//
// Returns the freshly-minted secret so the caller can store it.
func (h *AdminHandler) APICreateWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	uuidStr := chi.URLParam(r, "projectUuid")
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(uuidStr) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var body struct {
		TargetURL   string   `json:"target_url"`
		Events      []string `json:"events"`
		Description string   `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	ep, err := h.App.Webhooks.CreateEndpoint(pid, body.TargetURL, body.Description, body.Events)
	if err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_webhook", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.webhook.create", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"target_type":   "webhook_endpoint",
		"target_id":     int64(ep.ID),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"public_id":   ep.PublicID,
		"target_url":  ep.TargetURL,
		"events":      ep.Events,
		"status":      ep.Status,
		"description": ep.Description,
		"secret":      ep.Secret, // shown ONCE
	})
}
