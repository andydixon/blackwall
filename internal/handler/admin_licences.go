package handler

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/config"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

// ProjectLicences renders the scoped licence register for one project. Signed
// token bodies are loaded only for an explicit authenticated download request.
func (h *AdminHandler) ProjectLicences(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_licences") {
		return
	}
	projectID, projectName, projectUUID, ok := h.scopedLicenceProject(w, r)
	if !ok {
		return
	}
	licences, err := h.App.Licences.ListForProject(projectID)
	if err != nil {
		http.Error(w, "Unable to load licences", http.StatusInternalServerError)
		return
	}
	scope := h.scopeFor(r)
	data := h.adminBaseData(w, r, "Licences: "+projectName)
	data["Project"] = map[string]interface{}{"ID": projectID, "UUID": projectUUID, "Name": projectName}
	data["Licences"] = licences
	data["Now"] = time.Now().UTC()
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_licences")
	data["IssuanceEnabled"] = h.App.Licences.IssuanceReady()
	data["ActiveKeyID"] = h.App.Licences.ActiveKeyID()
	data["MaxValidityDays"] = h.App.Licences.MaxValidityDays()
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/licences.html", data)
}

// ProjectLicenceIssue validates operator input at the service boundary, signs
// with the dedicated Ed25519 key, persists the exact envelope, and records a
// non-PII audit event. Only super-administrators hold manage_licences.
func (h *AdminHandler) ProjectLicenceIssue(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_licences") {
		return
	}
	projectID, _, projectUUID, ok := h.scopedLicenceProject(w, r)
	if !ok {
		return
	}
	redirectURL := "/admin/projects/" + projectUUID + "/licences"
	if !h.adminLicenceMutationAllowed(actorID, "issue") {
		redirect(w, r, redirectURL+"?error=rate_limited")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, redirectURL+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.licence.issue"})
		sess.Save()
		redirect(w, r, redirectURL+"?error=csrf")
		return
	}
	maxInstances, _ := strconv.Atoi(r.FormValue("max_instances"))
	validityDays, _ := strconv.Atoi(r.FormValue("validity_days"))
	licence, err := h.App.Licences.Issue(service.LicenceIssueRequest{
		ProjectID:       projectID,
		ProjectUUID:     projectUUID,
		EntityType:      r.FormValue("entity_type"),
		EntityName:      r.FormValue("entity_name"),
		EntityReference: r.FormValue("entity_reference"),
		Hostnames:       splitLicenceList(r.FormValue("hostnames")),
		Features:        splitLicenceList(r.FormValue("features")),
		MaxInstances:    maxInstances,
		ValidityDays:    validityDays,
		IssuedByUserID:  actorID,
	})
	if err != nil {
		audit.LogFail("admin.licence.issue.fail", service.AuditMeta{
			"actor_user_id": actorID, "project_id": projectID,
			"project_uuid": projectUUID, "failure_reason": "input_or_signing_failure",
		})
		sess.Save()
		redirect(w, r, redirectURL+"?error=invalid")
		return
	}
	audit.LogSuccess("admin.licence.issue", service.AuditMeta{
		"actor_user_id": actorID, "project_id": projectID, "project_uuid": projectUUID,
		"target_type": "project_licence", "target_id": licence.PublicID,
	})
	sess.Save()
	redirect(w, r, redirectURL+"?success=issued")
}

// ProjectLicenceDownload returns the already-signed transport envelope. It
// re-verifies the stored signature first and prevents export under a key marked
// compromised.
func (h *AdminHandler) ProjectLicenceDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_licences") {
		return
	}
	projectID, _, _, ok := h.scopedLicenceProject(w, r)
	if !ok {
		return
	}
	licenceID := chi.URLParam(r, "licenceId")
	token, err := h.App.Licences.GetToken(projectID, licenceID)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Unable to export licence", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.blackwall.licence; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="blackwall-%s.bwlic"`, licenceID))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(token + "\n"))
}

func (h *AdminHandler) ProjectLicenceRevoke(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_licences") {
		return
	}
	projectID, _, projectUUID, ok := h.scopedLicenceProject(w, r)
	if !ok {
		return
	}
	redirectURL := "/admin/projects/" + projectUUID + "/licences"
	if !h.adminLicenceMutationAllowed(actorID, "revoke") {
		redirect(w, r, redirectURL+"?error=rate_limited")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, redirectURL+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.licence.revoke"})
		sess.Save()
		redirect(w, r, redirectURL+"?error=csrf")
		return
	}
	licenceID := chi.URLParam(r, "licenceId")
	if err := h.App.Licences.Revoke(projectID, licenceID, actorID, r.FormValue("reason")); err != nil {
		redirect(w, r, redirectURL+"?error=revoke_failed")
		return
	}
	audit.LogSuccess("admin.licence.revoke", service.AuditMeta{
		"actor_user_id": actorID, "project_id": projectID, "project_uuid": projectUUID,
		"target_type": "project_licence", "target_id": licenceID,
	})
	sess.Save()
	redirect(w, r, redirectURL+"?success=revoked")
}

func (h *AdminHandler) scopedLicenceProject(w http.ResponseWriter, r *http.Request) (int, string, string, bool) {
	projectUUID := chi.URLParam(r, "projectUuid")
	if !h.scopeFor(r).CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return 0, "", "", false
	}
	var projectID int
	var projectName string
	if err := h.DB.QueryRow(`SELECT id, name FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID, &projectName); err != nil {
		http.NotFound(w, r)
		return 0, "", "", false
	}
	return projectID, projectName, projectUUID, true
}

func (h *AdminHandler) adminLicenceMutationAllowed(actorID int, operation string) bool {
	if h.App.RateLimit == nil {
		return true
	}
	cfg := config.Get()
	return h.App.RateLimit.Check(
		fmt.Sprintf("user:%d", actorID), "admin.licence."+operation,
		cfg.AdminMutationRateLimitAttempts, cfg.AdminMutationRateLimitWindowSec,
	)
}

func splitLicenceList(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := strings.TrimSpace(field); value != "" {
			out = append(out, value)
		}
	}
	return out
}
