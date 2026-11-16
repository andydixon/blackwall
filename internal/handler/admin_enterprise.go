// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

// ─── Webhooks ────────────────────────────────────────────────────────────────

// WebhookList renders the webhook endpoints registered against a project plus
// a creation form. The page is the canonical admin surface for the feature.
func (h *AdminHandler) WebhookList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var projectID int
	var projectName string
	if err := h.DB.QueryRow(`SELECT id, name FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID, &projectName); err != nil {
		http.NotFound(w, r)
		return
	}
	endpoints, _ := h.App.Webhooks.ListForProject(projectID)
	feats, _ := h.App.Features.Get(projectID)

	data := h.adminBaseData(w, r, "Webhooks: "+projectName)
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName, "ID": projectID}
	data["Endpoints"] = endpoints
	data["WebhooksEnabled"] = feats.WebhooksEnabled
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_projects")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	data["NewSecret"] = r.URL.Query().Get("new_secret") // one-shot reveal on creation
	templates.AdminPage(w, "projects/webhooks.html", data)
}

// WebhookCreate adds a new endpoint. Server-generated secret is surfaced via
// the redirect query string ONCE — the admin must copy it then.
func (h *AdminHandler) WebhookCreate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	audit := getAudit(r)
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.webhook.create"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=csrf")
		return
	}
	var projectID int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	url := strings.TrimSpace(r.FormValue("target_url"))
	desc := strings.TrimSpace(r.FormValue("description"))
	eventsRaw := strings.TrimSpace(r.FormValue("events"))
	events := splitCommaList(eventsRaw)

	ep, err := h.App.Webhooks.CreateEndpoint(projectID, url, desc, events)
	if err != nil {
		audit.LogFail("admin.webhook.create.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"project_id":     projectID,
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=invalid")
		return
	}
	audit.LogSuccess("admin.webhook.create", service.AuditMeta{
		"actor_user_id": actorID,
		"project_id":    projectID,
		"project_uuid":  projectUUID,
		"target_type":   "webhook_endpoint",
		"target_id":     int64(ep.ID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?success=created&new_secret="+ep.Secret)
}

// WebhookUpdate edits an endpoint (URL, events, status, description, optionally rotates the secret).
func (h *AdminHandler) WebhookUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "endpointId")
	audit := getAudit(r)
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=csrf")
		return
	}
	rotate := r.FormValue("rotate_secret") == "1"
	ep, err := h.App.Webhooks.UpdateEndpoint(
		publicID,
		strings.TrimSpace(r.FormValue("target_url")),
		strings.TrimSpace(r.FormValue("description")),
		splitCommaList(r.FormValue("events")),
		r.FormValue("status"),
		rotate,
	)
	if err != nil {
		audit.LogFail("admin.webhook.update.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=invalid")
		return
	}
	audit.LogSuccess("admin.webhook.update", service.AuditMeta{
		"actor_user_id": actorID,
		"project_uuid":  projectUUID,
		"target_type":   "webhook_endpoint",
		"target_id":     int64(ep.ID),
	})
	sess.Save()
	tail := "?success=updated"
	if rotate {
		tail = "?success=secret_rotated&new_secret=" + ep.Secret
	}
	redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks"+tail)
}

// WebhookDelete removes a registered endpoint and all its delivery history.
func (h *AdminHandler) WebhookDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "endpointId")
	audit := getAudit(r)
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?error=csrf")
		return
	}
	if err := h.App.Webhooks.DeleteEndpoint(publicID); err == nil {
		audit.LogSuccess("admin.webhook.delete", service.AuditMeta{
			"actor_user_id": actorID,
			"project_uuid":  projectUUID,
			"target_type":   "webhook_endpoint",
		})
	}
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/webhooks?success=deleted")
}

// WebhookDeliveries lists recent delivery attempts for an endpoint so admins
// can debug failures without resorting to log scraping.
func (h *AdminHandler) WebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "endpointId")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ep, err := h.App.Webhooks.GetEndpoint(publicID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	deliveries, _ := h.App.Webhooks.ListDeliveries(ep.ID, 100)
	data := h.adminBaseData(w, r, "Webhook deliveries")
	data["Project"] = map[string]interface{}{"UUID": projectUUID}
	data["Endpoint"] = ep
	data["Deliveries"] = deliveries
	templates.AdminPage(w, "projects/webhook_deliveries.html", data)
}

// ─── Sessions ────────────────────────────────────────────────────────────────

// UserSessions lists a user's active server-recorded sessions. Available to
// any admin who can view the user; revocation needs manage_users.
func (h *AdminHandler) UserSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	userUUID := chi.URLParam(r, "userUuid")
	var userID int
	var userLabel string
	var orgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, u.display_label, o.uuid FROM users u
		LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.uuid=?`, userUUID).Scan(&userID, &userLabel, &orgUUID)
	if userID == 0 || !h.actorCanReachUser(scope, userID, orgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sessions, _ := h.App.Sessions.ListActiveForUser(userID)
	data := h.adminBaseData(w, r, "Sessions: "+userLabel)
	data["User"] = map[string]interface{}{"UUID": userUUID, "DisplayLabel": userLabel, "ID": userID}
	data["Sessions"] = sessions
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "users/sessions.html", data)
}

// UserSessionRevoke kills one specific session.
func (h *AdminHandler) UserSessionRevoke(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	userUUID := chi.URLParam(r, "userUuid")
	audit := getAudit(r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"/sessions?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/sessions?error=csrf")
		return
	}
	var userID int
	var orgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.uuid=?`, userUUID).Scan(&userID, &orgUUID)
	if !h.actorCanReachUser(scope, userID, orgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sid := r.FormValue("session_id")
	if err := h.App.Sessions.Revoke(sid, "admin_revoked"); err == nil {
		audit.LogSuccess("admin.session.revoke", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"target_type":    "user_session",
		})
	}
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/sessions?success=revoked")
}

// UserSessionRevokeAll kills every active session for the user.
func (h *AdminHandler) UserSessionRevokeAll(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	userUUID := chi.URLParam(r, "userUuid")
	audit := getAudit(r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"/sessions?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/sessions?error=csrf")
		return
	}
	var userID int
	var orgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.uuid=?`, userUUID).Scan(&userID, &orgUUID)
	if !h.actorCanReachUser(scope, userID, orgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := h.App.Sessions.RevokeAllForUser(userID, "admin_revoke_all"); err == nil {
		audit.LogSuccess("admin.session.revoke_all", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
		})
	}
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/sessions?success=revoked_all")
}

// ─── Branding ────────────────────────────────────────────────────────────────

// OrgBrandingUpdate updates the per-org branding overlay used by the login UI.
func (h *AdminHandler) OrgBrandingUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
	audit := getAudit(r)
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}
	var orgID int
	h.DB.QueryRow(`SELECT id FROM organizations WHERE uuid=?`, orgUUID).Scan(&orgID)
	if orgID == 0 {
		http.NotFound(w, r)
		return
	}
	err := h.App.Branding.Update(orgID,
		strings.TrimSpace(r.FormValue("logo_url")),
		strings.TrimSpace(r.FormValue("primary_color")),
		strings.TrimSpace(r.FormValue("login_message")),
		strings.TrimSpace(r.FormValue("support_email")))
	if err != nil {
		audit.LogFail("admin.org.branding.update.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=branding_invalid")
		return
	}
	audit.LogSuccess("admin.org.branding.update", service.AuditMeta{
		"actor_user_id":     actorID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
	})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=branding_updated")
}

// OrgDomainAdd registers a custom hostname against the organisation.
func (h *AdminHandler) OrgDomainAdd(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
	audit := getAudit(r)
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}
	var orgID int
	h.DB.QueryRow(`SELECT id FROM organizations WHERE uuid=?`, orgUUID).Scan(&orgID)
	if err := h.App.Branding.AddCustomDomain(orgID, r.FormValue("hostname")); err != nil {
		audit.LogFail("admin.org.domain.add.fail", service.AuditMeta{"actor_user_id": actorID, "failure_reason": err.Error()})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=domain_invalid")
		return
	}
	audit.LogSuccess("admin.org.domain.add", service.AuditMeta{"actor_user_id": actorID, "organization_id": orgID})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=domain_added")
}

// OrgDomainDelete removes a custom hostname mapping.
func (h *AdminHandler) OrgDomainDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
	audit := getAudit(r)
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}
	var orgID int
	h.DB.QueryRow(`SELECT id FROM organizations WHERE uuid=?`, orgUUID).Scan(&orgID)
	_ = h.App.Branding.DeleteCustomDomain(orgID, r.FormValue("hostname"))
	audit.LogSuccess("admin.org.domain.delete", service.AuditMeta{"actor_user_id": actorID, "organization_id": orgID})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=domain_deleted")
}

// ─── Audit chain checkpoints ────────────────────────────────────────────────

// AuditCheckpoints renders the checkpoint list + a manual "create now" button
// (job runs automatically too).
func (h *AdminHandler) AuditCheckpoints(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_audit") {
		return
	}
	ckpts, _ := h.App.AuditChain.ListCheckpoints(100)
	data := h.adminBaseData(w, r, "Audit chain checkpoints")
	data["Checkpoints"] = ckpts
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "audit/checkpoints.html", data)
}

// AuditCheckpointCreate forces an out-of-band checkpoint write.
func (h *AdminHandler) AuditCheckpointCreate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "view_audit") {
		return
	}
	audit := getAudit(r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/audit/checkpoints?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/audit/checkpoints?error=csrf")
		return
	}
	c, err := h.App.AuditChain.CreateCheckpoint()
	if err != nil {
		audit.LogFail("admin.audit.checkpoint.fail", service.AuditMeta{"actor_user_id": actorID, "failure_reason": err.Error()})
		sess.Save()
		redirect(w, r, "/admin/audit/checkpoints?error=create_failed")
		return
	}
	if c != nil {
		audit.LogSuccess("admin.audit.checkpoint.create", service.AuditMeta{
			"actor_user_id": actorID,
			"target_type":   "audit_chain_checkpoint",
			"target_id":     int64(c.ID),
		})
	}
	sess.Save()
	redirect(w, r, "/admin/audit/checkpoints?success=created")
}

// AuditCheckpointVerify runs the verify routine and reports back.
func (h *AdminHandler) AuditCheckpointVerify(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_audit") {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.Atoi(idStr)
	ckpts, _ := h.App.AuditChain.ListCheckpoints(1000)
	var found *service.Checkpoint
	for i := range ckpts {
		if ckpts[i].ID == id {
			found = &ckpts[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	err := h.App.AuditChain.VerifyCheckpoint(found)
	msg := "verified ok"
	status := "ok"
	if err != nil {
		msg = err.Error()
		status = "fail"
	}
	jsonOK(w, map[string]interface{}{
		"checkpoint_id": id,
		"status":        status,
		"message":       msg,
	})
}

// ─── Admin API tokens (UI) ─────────────────────────────────────────────────

// AdminTokens renders the actor's token list + create form. Tokens are
// scoped per-user; we only show the actor's own tokens.
func (h *AdminHandler) AdminTokens(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	tokens, _ := h.App.AdminTokens.ListForUser(actorID)
	data := h.adminBaseData(w, r, "API tokens", flashAdminTokenPlaintext, flashAdminTokenName)
	flashes := data["Flash"].(map[string]string)
	newToken := flashes[flashAdminTokenPlaintext]
	newTokenName := flashes[flashAdminTokenName]
	data["Tokens"] = tokens
	data["NewTokenPlaintext"] = newToken
	data["NewTokenName"] = newTokenName
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "admin_tokens.html", data)
}

// AdminTokenCreate mints a new token and reveals the plaintext once.
func (h *AdminHandler) AdminTokenCreate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	audit := getAudit(r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/api-tokens?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/api-tokens?error=csrf")
		return
	}
	name := r.FormValue("name")
	scopes := splitCommaList(r.FormValue("scopes"))
	var expiresPtr *time.Time
	if exp := strings.TrimSpace(r.FormValue("expires_at")); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			expiresPtr = &t
		}
	}
	tok, plaintext, err := h.App.AdminTokens.Create(actorID, name, scopes, expiresPtr)
	if err != nil {
		audit.LogFail("admin.token.create.fail", service.AuditMeta{"actor_user_id": actorID, "failure_reason": err.Error()})
		sess.Save()
		redirect(w, r, "/admin/api-tokens?error=invalid")
		return
	}
	audit.LogSuccess("admin.token.create", service.AuditMeta{
		"actor_user_id": actorID,
		"target_type":   "admin_api_token",
		"target_id":     int64(tok.ID),
	})
	sess.Set(flashAdminTokenPlaintext, plaintext)
	sess.Set(flashAdminTokenName, name)
	sess.Save()
	redirect(w, r, "/admin/api-tokens?success=created")
}

// AdminTokenRevoke kills a token.
func (h *AdminHandler) AdminTokenRevoke(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	audit := getAudit(r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/api-tokens?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/api-tokens?error=csrf")
		return
	}
	publicID := chi.URLParam(r, "publicId")
	_ = h.App.AdminTokens.Revoke(publicID)
	audit.LogSuccess("admin.token.revoke", service.AuditMeta{"actor_user_id": actorID, "target_type": "admin_api_token"})
	sess.Save()
	redirect(w, r, "/admin/api-tokens?success=revoked")
}

// ─── Project feature flags (UI) ────────────────────────────────────────────

// ProjectFeatureFlagsUpdate writes the toggles for a project.
func (h *AdminHandler) ProjectFeatureFlagsUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	audit := getAudit(r)
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"?error=csrf")
		return
	}
	var projectID int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	maxConc, _ := strconv.Atoi(r.FormValue("max_concurrent_sessions"))
	f := service.ProjectFeatures{
		ProjectID:             projectID,
		WebhooksEnabled:       r.FormValue("webhooks_enabled") == "1",
		DBSessionsEnabled:     r.FormValue("db_sessions_enabled") == "1",
		MaxConcurrentSessions: maxConc,
		CustomBrandingEnabled: r.FormValue("custom_branding_enabled") == "1",
		StepUpRequired:        r.FormValue("step_up_required") == "1",
	}
	if err := h.App.Features.Update(projectID, f); err != nil {
		audit.LogFail("admin.project.features.update.fail", service.AuditMeta{"actor_user_id": actorID, "failure_reason": err.Error()})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"?error=features_invalid")
		return
	}
	audit.LogSuccess("admin.project.features.update", service.AuditMeta{
		"actor_user_id": actorID,
		"project_id":    projectID,
		"project_uuid":  projectUUID,
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"?success=features_updated")
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// jsonAPIError emits a structured error to JSON API consumers.
func jsonAPIError(w http.ResponseWriter, status int, code, msg string) {
	if status >= http.StatusInternalServerError {
		msg = "internal server error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": msg,
	})
}
