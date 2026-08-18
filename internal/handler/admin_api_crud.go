package handler

// JSON admin API CRUD for the resources the Terraform provider needs to
// fully drive BlackWall declaratively: projects, OAuth clients, and SAML
// service providers. These endpoints reuse the same bearer-token middleware
// as the read-only surface in admin_api.go and gate writes on the matching
// capabilities (manage_projects / manage_clients).

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"blackwall/internal/service"
)

// ─── Projects ──────────────────────────────────────────────────────────────

// APICreateProject creates a new project under the supplied organisation.
// Mirrors the form-driven ProjectStore: enables feature-flag defaults,
// seeds the privilege ladder, but lives behind manage_projects rather than
// the UI's approval workflow because automation flows shouldn't bounce
// through human approval for create.
func (h *AdminHandler) APICreateProject(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	var body struct {
		Name             string `json:"name"`
		OrganizationUUID string `json:"organization_uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		jsonAPIError(w, http.StatusBadRequest, "missing_name", "name required")
		return
	}
	if body.OrganizationUUID == "" {
		jsonAPIError(w, http.StatusBadRequest, "missing_org", "organization_uuid required")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessOrganizationUUID(body.OrganizationUUID) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "organization out of scope")
		return
	}
	var orgID int
	h.DB.QueryRow(`SELECT id FROM organizations WHERE uuid=?`, body.OrganizationUUID).Scan(&orgID)
	if orgID == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "organization not found")
		return
	}

	projectUUID := uuid.NewString()
	var projID int64
	err := h.DB.QueryRow(`INSERT INTO projects (organization_id, uuid, name, status) VALUES (?,?,?,'active') RETURNING id`,
		orgID, projectUUID, name).Scan(&projID)
	if err != nil {
		jsonAPIError(w, http.StatusConflict, "create_failed", err.Error())
		return
	}

	// Seed privilege ladder identically to the UI path so SCIM / API users
	// have the same default assignment ladder available.
	defaults := []struct {
		Level int
		Name  string
	}{{1, "Owner"}, {2, "Administrator"}, {3, "Editor"}, {4, "Member"}, {5, "Viewer"}}
	for _, lv := range defaults {
		h.DB.Exec(`INSERT INTO project_privilege_levels (project_id, level, name) VALUES (?,?,?)`,
			projID, lv.Level, lv.Name)
	}
	// Enterprise-tier feature defaults on for new projects.
	if h.App.Features != nil {
		_ = h.App.Features.EnsureForNewProject(int(projID))
	}

	getAudit(r).LogSuccess("api.project.create", service.AuditMeta{
		"actor_user_id":     a.UserID,
		"organization_id":   orgID,
		"organization_uuid": body.OrganizationUUID,
		"target_type":       "project",
		"target_id":         projID,
		"project_uuid":      projectUUID,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/projects/"+projectUUID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"uuid":              projectUUID,
		"name":              name,
		"status":            "active",
		"organization_uuid": body.OrganizationUUID,
	})
}

// APIPatchProject updates name and/or status. Skips approval — automation
// is already a trusted surface (gated on a real admin role); a customer who
// wants approval-gated changes can use the UI flow.
func (h *AdminHandler) APIPatchProject(w http.ResponseWriter, r *http.Request) {
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
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if body.Name == nil && body.Status == nil {
		jsonAPIError(w, http.StatusBadRequest, "empty_patch", "at least one of name, status required")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	if body.Name != nil {
		if n := strings.TrimSpace(*body.Name); n != "" {
			h.DB.Exec(`UPDATE projects SET name=? WHERE id=?`, n, pid)
		}
	}
	if body.Status != nil {
		s := *body.Status
		if s != "active" && s != "disabled" {
			jsonAPIError(w, http.StatusBadRequest, "invalid_status", "status must be active or disabled")
			return
		}
		h.DB.Exec(`UPDATE projects SET status=? WHERE id=?`, s, pid)
	}
	getAudit(r).LogSuccess("api.project.update", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"project_uuid":  uuidStr,
		"target_type":   "project",
		"target_id":     int64(pid),
	})
	w.WriteHeader(http.StatusNoContent)
}

// APIDeleteProject disables the project (status = disabled). We do NOT
// actually drop the row — an OAuth client that depends on it should not
// silently start returning 404; the disabled status causes graceful
// rejection at the OAuth path and preserves audit lineage.
func (h *AdminHandler) APIDeleteProject(w http.ResponseWriter, r *http.Request) {
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
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	h.DB.Exec(`UPDATE projects SET status='disabled' WHERE id=?`, pid)
	getAudit(r).LogSuccess("api.project.disable", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"project_uuid":  uuidStr,
		"target_type":   "project",
		"target_id":     int64(pid),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ─── OAuth clients ─────────────────────────────────────────────────────────

// APICreateOAuthClient mints an OAuth client. Returns the generated
// client_secret in the response — shown ONCE, never again surfaced (we
// only persist the hash).
func (h *AdminHandler) APICreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_clients") {
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
		Name                 string   `json:"name"`
		ClientType           string   `json:"client_type"` // "confidential" (default) | "public"
		RedirectURIs         []string `json:"redirect_uris"`
		Grants               []string `json:"grants"`
		Scopes               []string `json:"scopes"`
		AccessTokenType      string   `json:"access_token_type"` // "jwt" | "opaque"
		AccessTokenLifetime  int      `json:"access_token_lifetime"`
		RefreshTokenLifetime int      `json:"refresh_token_lifetime"`
		OIDCEnabled          bool     `json:"oidc_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		jsonAPIError(w, http.StatusBadRequest, "missing_name", "name required")
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}

	confidential := body.ClientType != "public"
	clientPublicID := uuid.NewString()
	var clientSecret string
	var secretHashVal sql.NullString
	if confidential {
		clientSecret = hexToken(32)
		secretHashVal = sql.NullString{String: hashSecret(clientSecret), Valid: true}
	}
	if len(body.Grants) == 0 {
		body.Grants = []string{"authorization_code", "refresh_token"}
	}
	if body.AccessTokenType != "jwt" && body.AccessTokenType != "opaque" {
		body.AccessTokenType = "jwt"
	}
	if body.AccessTokenLifetime <= 0 {
		body.AccessTokenLifetime = 3600
	}
	if body.RefreshTokenLifetime <= 0 {
		body.RefreshTokenLifetime = 2592000
	}

	redirJSON, _ := json.Marshal(body.RedirectURIs)
	grantJSON, _ := json.Marshal(body.Grants)
	scopeJSON, _ := json.Marshal(body.Scopes)

	var newID int64
	err := h.DB.QueryRow(`INSERT INTO oauth_clients
		(project_id, client_id, client_secret_hash, name, redirect_uris, grants, scopes,
		 pkce_required, access_token_type, access_token_lifetime, refresh_token_lifetime, oidc_enabled, status)
		VALUES (?,?,?,?,?,?,?,TRUE,?,?,?,?,'active') RETURNING id`,
		pid, clientPublicID, secretHashVal, body.Name,
		string(redirJSON), string(grantJSON), string(scopeJSON),
		body.AccessTokenType, body.AccessTokenLifetime, body.RefreshTokenLifetime,
		body.OIDCEnabled).Scan(&newID)
	if err != nil {
		jsonAPIError(w, http.StatusConflict, "create_failed", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.client.create", service.AuditMeta{
		"actor_user_id":          a.UserID,
		"project_id":             pid,
		"project_uuid":           uuidStr,
		"target_type":            "oauth_client",
		"target_id":              newID,
		"oauth_client_public_id": clientPublicID,
	})
	resp := map[string]interface{}{
		"client_id":              clientPublicID,
		"name":                   body.Name,
		"status":                 "active",
		"oidc_enabled":           body.OIDCEnabled,
		"access_token_type":      body.AccessTokenType,
		"access_token_lifetime":  body.AccessTokenLifetime,
		"refresh_token_lifetime": body.RefreshTokenLifetime,
		"redirect_uris":          body.RedirectURIs,
		"grants":                 body.Grants,
		"scopes":                 body.Scopes,
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret // shown ONCE
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// APIGetOAuthClient returns a client by client_id (excluding the secret).
func (h *AdminHandler) APIGetOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	clientPublicID := chi.URLParam(r, "clientId")
	var pid int
	var name, status, accessTokenType, redirJSON, grantJSON, scopeJSON string
	var atLife, rtLife int
	var oidc bool
	err := h.DB.QueryRow(`SELECT project_id, name, status, access_token_type,
		access_token_lifetime, refresh_token_lifetime, oidc_enabled,
		redirect_uris, grants, scopes FROM oauth_clients WHERE client_id=?`,
		clientPublicID).Scan(&pid, &name, &status, &accessTokenType, &atLife, &rtLife, &oidc,
		&redirJSON, &grantJSON, &scopeJSON)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectID(pid) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var redir, grants, scopes []string
	_ = json.Unmarshal([]byte(redirJSON), &redir)
	_ = json.Unmarshal([]byte(grantJSON), &grants)
	_ = json.Unmarshal([]byte(scopeJSON), &scopes)
	jsonOK(w, map[string]interface{}{
		"client_id":              clientPublicID,
		"name":                   name,
		"status":                 status,
		"access_token_type":      accessTokenType,
		"access_token_lifetime":  atLife,
		"refresh_token_lifetime": rtLife,
		"oidc_enabled":           oidc,
		"redirect_uris":          redir,
		"grants":                 grants,
		"scopes":                 scopes,
	})
}

// APIPatchOAuthClient updates mutable fields. Secret rotation lives on a
// separate endpoint (POST /clients/{id}/rotate-secret) to avoid accidental
// rotation via a benign field update.
func (h *AdminHandler) APIPatchOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_clients") {
		return
	}
	clientPublicID := chi.URLParam(r, "clientId")
	var pid int
	h.DB.QueryRow(`SELECT project_id FROM oauth_clients WHERE client_id=?`, clientPublicID).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectID(pid) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	var body struct {
		Name                 *string  `json:"name"`
		Status               *string  `json:"status"`
		RedirectURIs         []string `json:"redirect_uris"`
		Grants               []string `json:"grants"`
		Scopes               []string `json:"scopes"`
		AccessTokenType      *string  `json:"access_token_type"`
		AccessTokenLifetime  *int     `json:"access_token_lifetime"`
		RefreshTokenLifetime *int     `json:"refresh_token_lifetime"`
		OIDCEnabled          *bool    `json:"oidc_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	updates := []string{}
	args := []interface{}{}
	if body.Name != nil {
		updates = append(updates, "name=?")
		args = append(args, *body.Name)
	}
	if body.Status != nil {
		if *body.Status != "active" && *body.Status != "disabled" {
			jsonAPIError(w, http.StatusBadRequest, "invalid_status", "status must be active or disabled")
			return
		}
		updates = append(updates, "status=?")
		args = append(args, *body.Status)
	}
	if body.RedirectURIs != nil {
		b, _ := json.Marshal(body.RedirectURIs)
		updates = append(updates, "redirect_uris=?")
		args = append(args, string(b))
	}
	if body.Grants != nil {
		b, _ := json.Marshal(body.Grants)
		updates = append(updates, "grants=?")
		args = append(args, string(b))
	}
	if body.Scopes != nil {
		b, _ := json.Marshal(body.Scopes)
		updates = append(updates, "scopes=?")
		args = append(args, string(b))
	}
	if body.AccessTokenType != nil {
		t := *body.AccessTokenType
		if t != "jwt" && t != "opaque" {
			jsonAPIError(w, http.StatusBadRequest, "invalid_token_type", "access_token_type must be jwt or opaque")
			return
		}
		updates = append(updates, "access_token_type=?")
		args = append(args, t)
	}
	if body.AccessTokenLifetime != nil {
		updates = append(updates, "access_token_lifetime=?")
		args = append(args, *body.AccessTokenLifetime)
	}
	if body.RefreshTokenLifetime != nil {
		updates = append(updates, "refresh_token_lifetime=?")
		args = append(args, *body.RefreshTokenLifetime)
	}
	if body.OIDCEnabled != nil {
		updates = append(updates, "oidc_enabled=?")
		args = append(args, *body.OIDCEnabled)
	}
	if len(updates) == 0 {
		jsonAPIError(w, http.StatusBadRequest, "empty_patch", "no fields to update")
		return
	}
	q := "UPDATE oauth_clients SET " + strings.Join(updates, ", ") + " WHERE client_id=?"
	args = append(args, clientPublicID)
	if _, err := h.DB.Exec(q, args...); err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.client.update", service.AuditMeta{
		"actor_user_id":          a.UserID,
		"project_id":             pid,
		"target_type":            "oauth_client",
		"oauth_client_public_id": clientPublicID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// APIDeleteOAuthClient disables the client (preserves token-lifecycle
// audit trail). Hard delete is intentionally not exposed via the JSON API
// — only the cookie path (with approval gating) can do that.
func (h *AdminHandler) APIDeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_clients") {
		return
	}
	clientPublicID := chi.URLParam(r, "clientId")
	var pid int
	h.DB.QueryRow(`SELECT project_id FROM oauth_clients WHERE client_id=?`, clientPublicID).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectID(pid) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	h.DB.Exec(`UPDATE oauth_clients SET status='disabled' WHERE client_id=?`, clientPublicID)
	getAudit(r).LogSuccess("api.client.disable", service.AuditMeta{
		"actor_user_id":          a.UserID,
		"project_id":             pid,
		"target_type":            "oauth_client",
		"oauth_client_public_id": clientPublicID,
	})
	w.WriteHeader(http.StatusNoContent)
}


// ─── SAML service providers ────────────────────────────────────────────────

// APIListSAMLSPs lists registered SPs under a project.
func (h *AdminHandler) APIListSAMLSPs(w http.ResponseWriter, r *http.Request) {
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
	sps, _ := h.App.SAML.ListSPsForProject(pid)
	out := make([]map[string]interface{}, 0, len(sps))
	for _, sp := range sps {
		out = append(out, samlSPToMap(&sp))
	}
	jsonOK(w, map[string]interface{}{"service_providers": out})
}

// APICreateSAMLSP registers a new SAML SP.
func (h *AdminHandler) APICreateSAMLSP(w http.ResponseWriter, r *http.Request) {
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
		EntityID     string            `json:"entity_id"`
		ACSURL       string            `json:"acs_url"`
		SLOURL       string            `json:"slo_url"`
		NameIDFormat string            `json:"name_id_format"`
		Audience     string            `json:"audience"`
		AttributeMap map[string]string `json:"attribute_map"`
		SPCertPEM    string            `json:"sp_cert_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, uuidStr).Scan(&pid)
	if pid == 0 {
		jsonAPIError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	sp, err := h.App.SAML.CreateSP(pid, body.EntityID, body.ACSURL, body.SLOURL,
		body.NameIDFormat, body.Audience, body.AttributeMap, body.SPCertPEM)
	if err != nil {
		jsonAPIError(w, http.StatusBadRequest, "invalid_sp", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.saml.sp.create", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    pid,
		"target_type":   "saml_service_provider",
		"target_id":     int64(sp.ID),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(samlSPToMap(sp))
}

// APIGetSAMLSP returns one SP by public_id.
func (h *AdminHandler) APIGetSAMLSP(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "view_projects") {
		return
	}
	publicID := chi.URLParam(r, "spId")
	sp, err := h.App.SAML.GetSP(publicID)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "service provider not found")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectID(sp.ProjectID) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	jsonOK(w, samlSPToMap(sp))
}

// APIDeleteSAMLSP removes an SP. Hard delete here is fine — SAML SPs hold
// no derived data; deleting the row simply stops the IdP from issuing
// assertions to that SP. SP-side users at the downstream app remain.
func (h *AdminHandler) APIDeleteSAMLSP(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_projects") {
		return
	}
	publicID := chi.URLParam(r, "spId")
	sp, err := h.App.SAML.GetSP(publicID)
	if err != nil {
		jsonAPIError(w, http.StatusNotFound, "not_found", "service provider not found")
		return
	}
	a := adminAPIActor(r)
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectID(sp.ProjectID) {
		jsonAPIError(w, http.StatusForbidden, "forbidden", "project out of scope")
		return
	}
	if err := h.App.SAML.DeleteSP(publicID); err != nil {
		jsonAPIError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	getAudit(r).LogSuccess("api.saml.sp.delete", service.AuditMeta{
		"actor_user_id": a.UserID,
		"project_id":    sp.ProjectID,
		"target_type":   "saml_service_provider",
		"target_id":     int64(sp.ID),
	})
	w.WriteHeader(http.StatusNoContent)
}

func samlSPToMap(sp *service.SAMLSP) map[string]interface{} {
	return map[string]interface{}{
		"public_id":       sp.PublicID,
		"entity_id":       sp.EntityID,
		"acs_url":         sp.ACSURL,
		"slo_url":         sp.SLOURL,
		"name_id_format":  sp.NameIDFormat,
		"audience":        sp.Audience,
		"sign_assertions": sp.SignAssertions,
		"sign_response":   sp.SignResponse,
		"sp_cert_pem":     sp.SPCertPEM,
		"attribute_map":   sp.AttributeMap,
		"status":          sp.Status,
	}
}

// (hexToken and hashSecret live in admin.go — same package.)
