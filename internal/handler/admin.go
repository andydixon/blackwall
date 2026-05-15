package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"blackwall/internal/buildinfo"
	"blackwall/internal/config"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

type AdminHandler struct {
	App      *App
	WebAuthn *service.WebAuthnService
	DB       *sql.DB
}

const adminLoginChallengeTTL = 120 * time.Second

// ─── Auth ────────────────────────────────────────────────────────────────────

func (h *AdminHandler) LoginForm(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	csrf := security.GenerateCSRF(sess)
	sess.Save()
	templates.Standalone(w, "admin/login.html", map[string]interface{}{
		"CSRFToken": csrf,
		"Version":   buildinfo.DisplayVersion(),
		"BuildDate": buildinfo.BuildDate,
	})
}

func (h *AdminHandler) LoginChallenge(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "webauthn.login.admin.challenge", 60, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "webauthn.login.admin.challenge"})
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeB64 := b64Std(challenge)

	sess.Set("webauthn_challenge", map[string]interface{}{
		"value":      challengeB64,
		"expires_at": time.Now().Add(adminLoginChallengeTTL).Unix(),
	})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]interface{}{
		"challenge":        challengeB64,
		"csrf_token":       nextCSRF,
		"timeout":          60000,
		"rpId":             h.WebAuthn.RPID(),
		"userVerification": "required",
	})
}

func (h *AdminHandler) LoginVerify(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	if !security.ValidateCSRF(sess, jsonStrField(body, "csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.login_verify"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "webauthn.login.admin.verify", 20, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "webauthn.login.admin.verify"})
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	credentialID := jsonStrField(body, "id")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")
	authenticatorData := jsonNestedStr(body, "response", "authenticatorData")
	signature := jsonNestedStr(body, "response", "signature")

	if credentialID == "" || clientDataJSON == "" || authenticatorData == "" || signature == "" {
		audit.LogFail("admin.login.fail", service.AuditMeta{"failure_reason": "Missing credential data"})
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	cred, err := h.WebAuthn.GetCredentialByPublicID(credentialID)
	if err != nil || cred == nil {
		audit.LogFail("webauthn.authentication.fail", service.AuditMeta{"failure_reason": "Credential not found", "webauthn_credential_public_id": credentialID})
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	challengeState := sess.Get("webauthn_challenge")
	expectedChallenge, expiresAt := extractChallenge(challengeState)
	if expectedChallenge == "" || (expiresAt > 0 && time.Now().Unix() > expiresAt) {
		sess.Delete("webauthn_challenge")
		audit.LogFail("webauthn.authentication.fail", service.AuditMeta{"failure_reason": "Challenge missing or expired", "webauthn_credential_public_id": credentialID})
		sess.Save()
		jsonError(w, "session_expired", http.StatusBadRequest)
		return
	}
	sess.Delete("webauthn_challenge")

	if ok, reason := h.WebAuthn.VerifyAssertionDetailed(credentialID, clientDataJSON, authenticatorData, signature, expectedChallenge); !ok {
		audit.LogFail("webauthn.authentication.fail", service.AuditMeta{"failure_reason": reason, "webauthn_credential_public_id": credentialID})
		sess.Save()
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	role, _ := h.App.AdminAuth.GetRole(cred.UserID)
	if role == "" {
		audit.LogFail("admin.login.fail", service.AuditMeta{"failure_reason": "Credential user lacks admin scope", "actor_user_id": cred.UserID, "webauthn_credential_id": cred.ID, "webauthn_credential_public_id": credentialID})
		sess.Save()
		jsonError(w, "invalid_credential", http.StatusForbidden)
		return
	}

	sess.Set("user_id", cred.UserID)
	sess.RegenerateID()

	audit.LogSuccess("admin.login.success", service.AuditMeta{"actor_user_id": cred.UserID, "webauthn_credential_id": cred.ID, "webauthn_credential_public_id": credentialID})
	sess.Save()

	jsonOK(w, map[string]interface{}{"success": true, "redirect": "/admin/dashboard"})
}

func (h *AdminHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/dashboard?error=bad_request")
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/dashboard?error=csrf")
		return
	}
	sess.Destroy()
	redirect(w, r, "/admin/login")
}

// ─── Auth middleware helpers ──────────────────────────────────────────────────

// requireAdminAuth gates every admin handler. It loads the user's effective
// scope (which encodes role + visible orgs/projects) and redirects to /admin/login
// if the visitor isn't a recognised admin.
func (h *AdminHandler) requireAdminAuth(w http.ResponseWriter, r *http.Request) (int, bool) {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	if userID == 0 {
		redirect(w, r, "/admin/login")
		return 0, false
	}
	scope := h.App.Scope.Build(userID)
	if !scope.IsAdmin {
		redirect(w, r, "/admin/login")
		return 0, false
	}
	return userID, true
}

// requireCapability returns true if the current admin can perform the named
// capability. If not, writes 403 and returns false (and the handler should
// stop processing).
func (h *AdminHandler) requireCapability(w http.ResponseWriter, r *http.Request, capability string) bool {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	scope := h.App.Scope.Build(userID)
	if security.HasCapability(scope.AdminRole, capability) {
		return true
	}
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Forbidden: missing capability " + capability))
	return false
}

// hasCapability is the read-only sibling of requireCapability for use in
// branching logic (e.g. show-or-hide UI elements).
func (h *AdminHandler) hasCapability(r *http.Request, capability string) bool {
	sess := security.PeekSession(r)
	userID := sess.GetInt("user_id")
	scope := h.App.Scope.Build(userID)
	return security.HasCapability(scope.AdminRole, capability)
}

// scopeFor returns the admin scope for the request's authenticated user.
func (h *AdminHandler) scopeFor(r *http.Request) *service.AdminScope {
	sess := security.PeekSession(r)
	userID := sess.GetInt("user_id")
	return h.App.Scope.Build(userID)
}

// adminBaseData supplies the values every admin template expects in its
// layout (title, current role, capability flags, CSRF token, impersonator).
func (h *AdminHandler) adminBaseData(w http.ResponseWriter, r *http.Request, title string) map[string]interface{} {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	scope := h.App.Scope.Build(userID)
	csrf := security.GenerateCSRF(sess)
	sess.Save()

	impersonator := sess.GetInt("impersonator_user_id")
	var impersonatorID interface{}
	if impersonator != 0 {
		impersonatorID = impersonator
	}

	caps := security.CapabilitiesFor(scope.AdminRole)
	capMap := make(map[string]bool, len(caps))
	for _, c := range caps {
		capMap[c] = true
	}

	return map[string]interface{}{
		"Title":              title,
		"CurrentAdminRole":   scope.AdminRole,
		"IsSuperAdmin":       scope.IsSuperAdmin,
		"IsAdmin":            scope.IsAdmin,
		"Capabilities":       capMap,
		"ScopeProjectIDs":    scope.ProjectIDs,
		"ScopeProjectUUIDs":  scope.ProjectUUIDs,
		"ScopeOrgIDs":        scope.OrganizationIDs,
		"ScopeOrgUUIDs":      scope.OrganizationUUIDs,
		"ImpersonatorUserID": impersonatorID,
		"CSRFToken":          csrf,
	}
}

// canActorActDirectly returns true if the current actor's role grants the
// named direct-mutation capability (e.g. "update_project_settings_direct").
// Used by handlers to decide between applying a change immediately vs
// enqueueing an approval request.
func (h *AdminHandler) canActorActDirectly(r *http.Request, capability string) bool {
	sess := security.PeekSession(r)
	userID := sess.GetInt("user_id")
	scope := h.App.Scope.Build(userID)
	return security.HasCapability(scope.AdminRole, capability)
}

// actorCanReachUser returns true when the actor's scope grants visibility on
// the target user — either because the user belongs to an organisation the
// actor administers, or the user is assigned to a project in the actor's
// scope. Super-admins always pass. This is the IDOR gate for every per-user
// mutation endpoint.
func (h *AdminHandler) actorCanReachUser(scope *service.AdminScope, targetUserID int, targetOrgUUID string) bool {
	if scope.IsSuperAdmin {
		return true
	}
	if targetOrgUUID != "" && scope.CanAccessOrganizationUUID(targetOrgUUID) {
		return true
	}
	if targetUserID < 1 {
		return false
	}
	// Fallback: user might be assigned to a project the actor can see even if
	// their home organisation isn't in the actor's scope.
	rows, err := h.DB.Query(`SELECT project_id FROM user_project_roles WHERE user_id=?`, targetUserID)
	if err != nil {
		return false
	}
	defer rows.Close()
	var projectIDs []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err == nil {
			projectIDs = append(projectIDs, pid)
		}
	}
	return scope.CanAccessUserByProjects(projectIDs)
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

// Dashboard renders the admin home page. Stats are scoped: super-admins see
// global totals, organisation operators see only counts for projects in their
// scope. Mirrors AdminController::dashboard() including the
// success/fail rollups and the top-12 event-type breakdowns.
func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "view_dashboard") {
		return
	}
	scope := h.App.Scope.Build(userID)

	type stats struct {
		Users      int
		Projects   int
		Clients    int
		AuditCount int
	}
	type periodCounts struct {
		Today int
		Week  int
		Month int
	}
	type outcomeBreakdown struct {
		Success periodCounts
		Fail    periodCounts
	}
	type cryptbinStats struct {
		Created24h int
		Failed24h  int
	}

	var s stats
	outcomeStats := outcomeBreakdown{}
	var successBreakdown, failBreakdown []map[string]interface{}
	var recentAudit []map[string]interface{}
	cryptbin := cryptbinStats{}

	hasScope := scope.IsSuperAdmin || len(scope.ProjectIDs) > 0
	if hasScope {
		// Counts and recent activity, scoped or global.
		var projectFilter string
		var args []interface{}
		if !scope.IsSuperAdmin {
			ph, ids := inClausePlaceholders(scope.ProjectIDs)
			projectFilter = " WHERE project_id IN (" + ph + ")"
			args = ids
		}

		if scope.IsSuperAdmin {
			h.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&s.Users)
			h.DB.QueryRow("SELECT COUNT(*) FROM projects").Scan(&s.Projects)
			h.DB.QueryRow("SELECT COUNT(*) FROM oauth_clients").Scan(&s.Clients)
			h.DB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&s.AuditCount)
		} else {
			ph, ids := inClausePlaceholders(scope.ProjectIDs)
			h.DB.QueryRow(`SELECT COUNT(DISTINCT user_id) FROM user_project_roles WHERE project_id IN (`+ph+`)`, ids...).Scan(&s.Users)
			h.DB.QueryRow(`SELECT COUNT(*) FROM projects WHERE id IN (`+ph+`)`, ids...).Scan(&s.Projects)
			h.DB.QueryRow(`SELECT COUNT(*) FROM oauth_clients WHERE project_id IN (`+ph+`)`, ids...).Scan(&s.Clients)
			h.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE project_id IN (`+ph+`)`, ids...).Scan(&s.AuditCount)
		}

		// Recent activity (10 latest)
		recentQ := `SELECT event_type, outcome, actor_user_uuid, created_at FROM audit_log` + projectFilter + ` ORDER BY created_at DESC LIMIT 10`
		if rows, err := h.DB.Query(recentQ, args...); err == nil {
			for rows.Next() {
				var eventType, outcome string
				var actorUUID sql.NullString
				var createdAt time.Time
				rows.Scan(&eventType, &outcome, &actorUUID, &createdAt)
				recentAudit = append(recentAudit, map[string]interface{}{
					"EventType": eventType,
					"Outcome":   outcome,
					"ActorUUID": actorUUID.String,
					"CreatedAt": createdAt.Format("2006-01-02 15:04"),
				})
			}
			rows.Close()
		}

		// Outcome rollups per period.
		outcomeQ := `SELECT outcome,
		             SUM(created_at >= CURDATE())                          AS today_count,
		             SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY))    AS week_count,
		             SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))   AS month_count
		             FROM audit_log
		             WHERE outcome IN ('success','fail')` +
			scopeAndClause(scope.IsSuperAdmin, scope.ProjectIDs) +
			` GROUP BY outcome`
		if rows, err := h.DB.Query(outcomeQ, scopeArgs(scope.IsSuperAdmin, scope.ProjectIDs)...); err == nil {
			for rows.Next() {
				var outcome string
				var today, week, month sql.NullInt64
				rows.Scan(&outcome, &today, &week, &month)
				pc := periodCounts{Today: int(today.Int64), Week: int(week.Int64), Month: int(month.Int64)}
				if outcome == "success" {
					outcomeStats.Success = pc
				} else if outcome == "fail" {
					outcomeStats.Fail = pc
				}
			}
			rows.Close()
		}

		// Top 12 event-types by month, for both success and fail.
		successBreakdown = h.eventTypeBreakdown(scope, "success")
		failBreakdown = h.eventTypeBreakdown(scope, "fail")

		// Cryptbin recent activity stats — only super-admins see these.
		if scope.IsSuperAdmin {
			h.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type='cryptbin.create.success' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)`).Scan(&cryptbin.Created24h)
			h.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type LIKE 'cryptbin.%' AND outcome='fail' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)`).Scan(&cryptbin.Failed24h)
		}
	}

	// Approval data — visible if the actor has view_approvals.
	var approvalSummary service.ApprovalSummary
	var approvalSLA service.ApprovalSLA
	var pendingApprovalsList []service.ApprovalRequest
	canViewApprovals := security.HasCapability(scope.AdminRole, "view_approvals")
	if canViewApprovals {
		approvalSummary, _ = h.App.Approval.SummariseVisibleToUser(userID, scope.IsSuperAdmin, scope.ProjectIDs)
		approvalSLA, _ = h.App.Approval.SummariseSlaVisibleToUser(userID, scope.IsSuperAdmin, scope.ProjectIDs, config.Get().AdminApprovalPendingWarnDays)
		pendingApprovalsList, _ = h.App.Approval.ListPendingByRequester(userID, 6)
	}

	// CSRF security event stats — useful early-warning indicator on the dashboard.
	csrfStats := h.dashboardSecurityEventStats("security.csrf.fail", scope)

	data := h.adminBaseData(w, r, "Dashboard")
	data["Stats"] = s
	data["OutcomeStats"] = outcomeStats
	data["SuccessBreakdown"] = successBreakdown
	data["FailBreakdown"] = failBreakdown
	data["RecentAudit"] = recentAudit
	data["CryptbinStats"] = cryptbin
	data["ApprovalSummary"] = approvalSummary
	data["ApprovalSLA"] = approvalSLA
	data["MyPendingApprovals"] = pendingApprovalsList
	data["CSRFSecurityStats"] = csrfStats
	data["CanViewApprovals"] = canViewApprovals
	data["CanViewCryptbin"] = security.HasCapability(scope.AdminRole, "view_cryptbin")

	templates.AdminPage(w, "dashboard.html", data)
}

// eventTypeBreakdown returns the top 12 event types for the given outcome
// in the last 30 days, scoped to the admin's visible projects.
func (h *AdminHandler) eventTypeBreakdown(scope *service.AdminScope, outcome string) []map[string]interface{} {
	q := `SELECT event_type,
	             SUM(created_at >= CURDATE())                          AS today_count,
	             SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY))    AS week_count,
	             SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))   AS month_count
	      FROM audit_log
	      WHERE outcome = ?
	        AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)` +
		scopeAndClause(scope.IsSuperAdmin, scope.ProjectIDs) +
		` GROUP BY event_type
	      ORDER BY month_count DESC, week_count DESC, today_count DESC, event_type ASC
	      LIMIT 12`
	args := append([]interface{}{outcome}, scopeArgs(scope.IsSuperAdmin, scope.ProjectIDs)...)
	rows, err := h.DB.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var et string
		var today, week, month sql.NullInt64
		rows.Scan(&et, &today, &week, &month)
		out = append(out, map[string]interface{}{
			"EventType": et,
			"Today":     int(today.Int64),
			"Week":      int(week.Int64),
			"Month":     int(month.Int64),
		})
	}
	return out
}

// dashboardSecurityEventStats returns today/week/month counts for a specific
// security event type, scoped to the admin's visible projects.
func (h *AdminHandler) dashboardSecurityEventStats(eventType string, scope *service.AdminScope) map[string]int {
	q := `SELECT
	        COALESCE(SUM(created_at >= CURDATE()), 0)                          AS today_count,
	        COALESCE(SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)), 0)    AS week_count,
	        COALESCE(SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)), 0)   AS month_count
	      FROM audit_log
	      WHERE event_type = ?` +
		scopeAndClause(scope.IsSuperAdmin, scope.ProjectIDs)
	args := append([]interface{}{eventType}, scopeArgs(scope.IsSuperAdmin, scope.ProjectIDs)...)
	var today, week, month sql.NullInt64
	h.DB.QueryRow(q, args...).Scan(&today, &week, &month)
	return map[string]int{
		"Today": int(today.Int64),
		"Week":  int(week.Int64),
		"Month": int(month.Int64),
	}
}

// scopeAndClause returns " AND project_id IN (?,?,?)" for non-super-admin
// scopes, or empty string for super-admin (visibility wide open).
func scopeAndClause(isSuperAdmin bool, projectIDs []int) string {
	if isSuperAdmin {
		return ""
	}
	if len(projectIDs) == 0 {
		// Non-super-admin with zero projects sees nothing.
		return " AND 1=0"
	}
	ph, _ := inClausePlaceholders(projectIDs)
	return " AND project_id IN (" + ph + ")"
}

// scopeArgs returns the IN-clause parameter list to pair with scopeAndClause.
func scopeArgs(isSuperAdmin bool, projectIDs []int) []interface{} {
	if isSuperAdmin || len(projectIDs) == 0 {
		return nil
	}
	out := make([]interface{}, len(projectIDs))
	for i, id := range projectIDs {
		out[i] = id
	}
	return out
}

func inClausePlaceholders(ids []int) (string, []interface{}) {
	if len(ids) == 0 {
		return "", nil
	}
	parts := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		parts[i] = "?"
		args[i] = id
	}
	return strings.Join(parts, ","), args
}

// ─── Users ───────────────────────────────────────────────────────────────────

// UsersList shows the user roster. Super-admins see every user; org admins
// only see users assigned to a project in their scope.
func (h *AdminHandler) UsersList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_users") {
		return
	}
	scope := h.scopeFor(r)

	var users []map[string]interface{}
	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query(`SELECT u.id, u.uuid, u.display_label, u.status, u.created_at,
		                             COALESCE(o.name, '') AS organization_name
		                      FROM users u
		                      LEFT JOIN organizations o ON o.id = u.organization_id
		                      ORDER BY u.created_at DESC`)
	} else if len(scope.ProjectIDs) > 0 {
		ph, args := inClausePlaceholders(scope.ProjectIDs)
		q := `SELECT DISTINCT u.id, u.uuid, u.display_label, u.status, u.created_at,
		                     COALESCE(o.name, '') AS organization_name
		      FROM users u
		      JOIN user_project_roles upr ON upr.user_id = u.id
		      LEFT JOIN organizations o ON o.id = u.organization_id
		      WHERE upr.project_id IN (` + ph + `)
		      ORDER BY u.created_at DESC`
		rows, _ = h.DB.Query(q, args...)
	}

	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var uid, label, status, orgName string
			var createdAt time.Time
			rows.Scan(&id, &uid, &label, &status, &createdAt, &orgName)
			users = append(users, map[string]interface{}{
				"ID":               id,
				"UUID":             uid,
				"DisplayLabel":     label,
				"Status":           status,
				"CreatedAt":        createdAt,
				"OrganizationName": orgName,
			})
		}
	}

	data := h.adminBaseData(w, r, "Users")
	data["Users"] = users
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_users")
	templates.AdminPage(w, "users/list.html", data)
}

// UserCreate renders the new-user form. The org dropdown is filtered to the
// actor's visible organisations (or all, for super-admins).
func (h *AdminHandler) UserCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)

	var orgs []map[string]interface{}
	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query("SELECT id, uuid, name FROM organizations WHERE status='active' ORDER BY name")
	} else if len(scope.OrganizationIDs) > 0 {
		ph, args := inClausePlaceholders(scope.OrganizationIDs)
		rows, _ = h.DB.Query("SELECT id, uuid, name FROM organizations WHERE id IN ("+ph+") AND status='active' ORDER BY name", args...)
	}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var uid, name string
			rows.Scan(&id, &uid, &name)
			orgs = append(orgs, map[string]interface{}{"ID": id, "UUID": uid, "Name": name})
		}
	}

	data := h.adminBaseData(w, r, "Create User")
	data["Organizations"] = orgs
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "users/create.html", data)
}

func (h *AdminHandler) UserStore(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/create?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.user.create"})
		sess.Save()
		redirect(w, r, "/admin/users/create?error=csrf")
		return
	}

	label := strings.TrimSpace(r.FormValue("display_label"))
	orgUUID := r.FormValue("organization_uuid")
	status := r.FormValue("status")
	if status != "active" && status != "disabled" {
		status = "active"
	}

	if label == "" || len(label) > 120 {
		redirect(w, r, "/admin/users/create?error=invalid")
		return
	}
	// Reject the actor inserting a user into an org they don't control.
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		audit.LogFail("admin.user.create.fail", service.AuditMeta{
			"actor_user_id":     actorID,
			"organization_uuid": orgUUID,
			"failure_reason":    "Organization out of scope",
		})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var orgID int
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)
	if orgID == 0 {
		redirect(w, r, "/admin/users/create?error=invalid_org")
		return
	}

	userUUID := uuid.NewString()
	res, err := h.DB.Exec("INSERT INTO users (organization_id, uuid, display_label, status) VALUES (?,?,?,?)", orgID, userUUID, label, status)
	if err != nil {
		redirect(w, r, "/admin/users/create?error=duplicate")
		return
	}
	newUserID, _ := res.LastInsertId()

	// Enrolment tokens are stored hashed (SHA-256) — the URL carries the raw
	// token so the recipient can use it once, but the database row never
	// holds the bearer secret in plaintext.
	token := hexToken(32)
	tokenHash := security.HashToken(token)
	expiry := time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_token_"+tokenHash, fmt.Sprintf("%d", newUserID))
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_expiry_"+tokenHash, expiry)

	audit.LogSuccess("admin.user.create", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_user_id":    newUserID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
		"target_type":       "user",
		"target_id":         newUserID,
	})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"?success=created&enrollment_token="+token)
}

// UserDetail shows the full user record: profile, status, WebAuthn
// credentials, and the project assignments granting them access.
func (h *AdminHandler) UserDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_users") {
		return
	}
	scope := h.scopeFor(r)

	userUUID := chi.URLParam(r, "userUuid")

	var id, orgID int
	var label, status string
	var orgUUID, orgName string
	var createdAt time.Time
	err := h.DB.QueryRow(`SELECT u.id, u.uuid, u.display_label, u.status, u.created_at,
	                            u.organization_id, COALESCE(o.uuid, ''), COALESCE(o.name, '')
	                     FROM users u
	                     LEFT JOIN organizations o ON o.id = u.organization_id
	                     WHERE u.uuid = ?`, userUUID).Scan(&id, &userUUID, &label, &status, &createdAt, &orgID, &orgUUID, &orgName)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Project IDs this user is assigned to — used both for the UI and to
	// gate visibility for org admins.
	var userProjectIDs []int
	prows, _ := h.DB.Query(`SELECT project_id FROM user_project_roles WHERE user_id=?`, id)
	if prows != nil {
		for prows.Next() {
			var pid int
			prows.Scan(&pid)
			userProjectIDs = append(userProjectIDs, pid)
		}
		prows.Close()
	}
	if !scope.CanAccessUserByProjects(userProjectIDs) && orgID != 0 && !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	user := map[string]interface{}{
		"ID":               id,
		"UUID":             userUUID,
		"DisplayLabel":     label,
		"Status":           status,
		"CreatedAt":        createdAt,
		"OrganizationUUID": orgUUID,
		"OrganizationName": orgName,
	}

	creds, _ := h.DB.Query("SELECT id, credential_id, label, created_at, last_used_at, sign_counter FROM webauthn_credentials WHERE user_id=? ORDER BY created_at DESC", id)
	var credentials []map[string]interface{}
	if creds != nil {
		defer creds.Close()
		for creds.Next() {
			var cid, signCount int
			var credPubID string
			var clabel sql.NullString
			var cat time.Time
			var luat sql.NullTime
			creds.Scan(&cid, &credPubID, &clabel, &cat, &luat, &signCount)
			credentials = append(credentials, map[string]interface{}{
				"ID":           cid,
				"CredentialID": credPubID,
				"Label":        clabel.String,
				"CreatedAt":    cat,
				"LastUsedAt":   luat,
				"SignCounter":  signCount,
			})
		}
	}

	// Project assignments
	var assignments []map[string]interface{}
	arows, _ := h.DB.Query(`SELECT upr.id, p.uuid, p.name, upr.privilege_level, COALESCE(pl.name, '') AS pl_name
	                        FROM user_project_roles upr
	                        JOIN projects p ON p.id = upr.project_id
	                        LEFT JOIN project_privilege_levels pl ON pl.project_id = upr.project_id AND pl.level = upr.privilege_level
	                        WHERE upr.user_id = ? ORDER BY p.name`, id)
	if arows != nil {
		for arows.Next() {
			var aid, level int
			var puuid, pname, plName string
			arows.Scan(&aid, &puuid, &pname, &level, &plName)
			assignments = append(assignments, map[string]interface{}{
				"ID":             aid,
				"ProjectUUID":    puuid,
				"ProjectName":    pname,
				"PrivilegeLevel": level,
				"PrivilegeLabel": service.ResolvePrivilegeLabel(level, plName),
			})
		}
		arows.Close()
	}

	enrollToken := r.URL.Query().Get("enrollment_token")
	cfg := config.Get()
	var enrollmentLink string
	if enrollToken != "" {
		enrollmentLink = cfg.AppURL + "/enroll?token=" + enrollToken
	}

	data := h.adminBaseData(w, r, "User: "+label)
	data["User"] = user
	data["Credentials"] = credentials
	data["Assignments"] = assignments
	data["EnrollmentLink"] = enrollmentLink
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_users")
	data["CanDirectStatus"] = security.HasCapability(scope.AdminRole, "change_user_status_direct")
	data["CanDirectDelete"] = security.HasCapability(scope.AdminRole, "delete_credentials_direct")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "users/detail.html", data)
}

// UserUpdate updates display_label and status. Status changes are
// gated by the change_user_status_direct capability — actors without it have
// the change enqueued as an approval request rather than applied immediately.
func (h *AdminHandler) UserUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	userUUID := chi.URLParam(r, "userUuid")

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.user.update"})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"?error=csrf")
		return
	}

	var userID int
	var currentStatus string
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, u.status, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &currentStatus, &targetOrgUUID)
	if userID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		audit.LogFail("admin.user.update.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"failure_reason": "User out of scope",
		})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	label := strings.TrimSpace(r.FormValue("display_label"))
	status := r.FormValue("status")

	// Profile updates are always direct.
	if label != "" {
		h.DB.Exec("UPDATE users SET display_label=? WHERE id=?", label, userID)
	}

	// Status mutation: route through approval workflow if the actor lacks
	// direct authority. Skip both if the new value is invalid or unchanged.
	if (status == "active" || status == "disabled") && status != currentStatus {
		canDirect := h.canActorActDirectly(r, "change_user_status_direct")
		if canDirect {
			h.DB.Exec("UPDATE users SET status=? WHERE id=?", status, userID)
			audit.LogSuccess("admin.user.status.update", service.AuditMeta{
				"actor_user_id":  actorID,
				"target_user_id": userID,
				"target_type":    "user",
				"target_id":      int64(userID),
				"new_status":     status,
				"old_status":     currentStatus,
			})
		} else {
			payload := map[string]interface{}{
				"target_user_uuid": userUUID,
				"target_user_id":   userID,
				"new_status":       status,
				"current_status":   currentStatus,
				"requested_at":     time.Now().UTC().Format(time.RFC3339),
			}
			id, err := h.App.Approval.Create("user.status.change", payload, actorID, nil)
			if err != nil {
				redirect(w, r, "/admin/users/"+userUUID+"?error=approval_failed")
				return
			}
			audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
				"actor_user_id":  actorID,
				"target_user_id": userID,
				"target_type":    "approval_request",
				"target_id":      id,
				"action_type":    "user.status.change",
			})
			sess.Save()
			redirect(w, r, "/admin/users/"+userUUID+"?success=pending_approval")
			return
		}
	}

	audit.LogSuccess("admin.user.update", service.AuditMeta{"actor_user_id": actorID, "target_user_id": userID})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"?success=updated")
}

func (h *AdminHandler) GenerateEnrollmentLink(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	userUUID := chi.URLParam(r, "userUuid")

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.enrollment_link"})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"?error=csrf")
		return
	}

	var userID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &targetOrgUUID)
	if userID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		audit.LogFail("admin.enrollment_link.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"failure_reason": "User out of scope",
		})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Hash the bearer-secret half before persisting; the URL carries the raw
	// token but the database column never holds the unhashed value.
	token := hexToken(32)
	tokenHash := security.HashToken(token)
	expiry := time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_token_"+tokenHash, fmt.Sprintf("%d", userID))
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_expiry_"+tokenHash, expiry)

	audit.LogSuccess("admin.enrollment_link.generate", service.AuditMeta{
		"actor_user_id":  actorID,
		"target_user_id": userID,
		"target_type":    "user",
		"target_id":      int64(userID),
	})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"?success=enrollment_link&enrollment_token="+token)
}

// DeleteCredential removes a WebAuthn passkey from a user account. If the
// actor lacks delete_credentials_direct, the deletion is routed through the
// approval workflow instead.
func (h *AdminHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	audit := getAudit(r)
	userUUID := chi.URLParam(r, "userUuid")
	credPublicID := chi.URLParam(r, "credentialPublicId")

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.delete_credential"})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"?error=csrf")
		return
	}

	var credID, credUserID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT wc.id, wc.user_id, o.uuid
	               FROM webauthn_credentials wc
	               JOIN users u ON u.id = wc.user_id
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE wc.credential_id = ? AND u.uuid = ?`,
		credPublicID, userUUID).Scan(&credID, &credUserID, &targetOrgUUID)
	if credID == 0 {
		http.NotFound(w, r)
		return
	}
	scope := h.scopeFor(r)
	if !h.actorCanReachUser(scope, credUserID, targetOrgUUID.String) {
		audit.LogFail("admin.credential.delete.fail", service.AuditMeta{
			"actor_user_id":          actorID,
			"target_user_id":         credUserID,
			"webauthn_credential_id": credID,
			"failure_reason":         "User out of scope",
		})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	canDirect := h.canActorActDirectly(r, "delete_credentials_direct")
	if !canDirect {
		payload := map[string]interface{}{
			"target_user_uuid":              userUUID,
			"target_user_id":                credUserID,
			"webauthn_credential_id":        credID,
			"webauthn_credential_public_id": credPublicID,
			"requested_at":                  time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("credential.delete", payload, actorID, nil)
		if err != nil {
			redirect(w, r, "/admin/users/"+userUUID+"?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":          actorID,
			"target_user_id":         credUserID,
			"webauthn_credential_id": credID,
			"target_type":            "approval_request",
			"target_id":              id,
			"action_type":            "credential.delete",
		})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"?success=pending_approval")
		return
	}

	h.DB.Exec("DELETE FROM webauthn_credentials WHERE id=?", credID)
	audit.LogSuccess("admin.credential.delete", service.AuditMeta{
		"actor_user_id":          actorID,
		"target_user_id":         credUserID,
		"webauthn_credential_id": credID,
	})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"?success=credential_deleted")
}

// ─── Custom OIDC claims ──────────────────────────────────────────────────────
//
// Two surfaces:
//   * user-level claims that ride on every ID token / userinfo for that user
//   * project-scoped claims that only appear when the token is bound to a
//     project the user is assigned to (so different downstream apps can see
//     different per-user attributes without leaking across projects).

// UserClaims renders the claims management page for a single user. It shows:
//   - the user-level claim table (cross-project)
//   - one project-scoped claim table per project the user is assigned to
//     AND the actor can see in their scope.
func (h *AdminHandler) UserClaims(w http.ResponseWriter, r *http.Request) {
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
	var targetOrgUUID sql.NullString
	err := h.DB.QueryRow(`SELECT u.id, u.display_label, o.uuid
	                     FROM users u
	                     LEFT JOIN organizations o ON o.id = u.organization_id
	                     WHERE u.uuid = ?`, userUUID).Scan(&userID, &userLabel, &targetOrgUUID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	userClaims, _ := h.App.Claims.ListUserClaims(userID)

	// Per-project tables: only projects the user is assigned to AND the
	// actor can access. Filtering both ways prevents an org admin from
	// reading a different org's project claims via this page.
	type projectClaimSet struct {
		ProjectID   int
		ProjectUUID string
		ProjectName string
		Claims      []service.OIDCClaim
	}
	var projectSets []projectClaimSet
	prows, _ := h.DB.Query(`SELECT p.id, p.uuid, p.name
	                        FROM user_project_roles upr
	                        JOIN projects p ON p.id = upr.project_id
	                        WHERE upr.user_id = ?
	                        ORDER BY p.name`, userID)
	if prows != nil {
		defer prows.Close()
		for prows.Next() {
			var pid int
			var puuid, pname string
			prows.Scan(&pid, &puuid, &pname)
			if !scope.CanAccessProjectID(pid) {
				continue
			}
			cl, _ := h.App.Claims.ListProjectClaims(userID, pid)
			projectSets = append(projectSets, projectClaimSet{
				ProjectID: pid, ProjectUUID: puuid, ProjectName: pname, Claims: cl,
			})
		}
	}

	data := h.adminBaseData(w, r, "Claims: "+userLabel)
	data["User"] = map[string]interface{}{"UUID": userUUID, "DisplayLabel": userLabel, "ID": userID}
	data["UserClaims"] = userClaims
	data["ProjectClaimSets"] = projectSets
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "users/claims.html", data)
}

// UserClaimUpsert sets or updates a user-level custom OIDC claim.
func (h *AdminHandler) UserClaimUpsert(w http.ResponseWriter, r *http.Request) {
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
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.claims.user.upsert"})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=csrf")
		return
	}

	var userID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &targetOrgUUID)
	if userID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	key := strings.TrimSpace(r.FormValue("claim_key"))
	value := r.FormValue("claim_value")
	if err := h.App.Claims.SetUserClaim(userID, key, value); err != nil {
		audit.LogFail("admin.claims.user.upsert.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"claim_key":      key,
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=invalid")
		return
	}
	audit.LogSuccess("admin.claims.user.upsert", service.AuditMeta{
		"actor_user_id":  actorID,
		"target_user_id": userID,
		"target_type":    "user_oidc_claim",
		"target_id":      int64(userID),
		"claim_key":      key,
	})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/claims?success=updated")
}

// UserClaimDelete removes a user-level claim.
func (h *AdminHandler) UserClaimDelete(w http.ResponseWriter, r *http.Request) {
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
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=csrf")
		return
	}

	var userID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &targetOrgUUID)
	if userID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	key := strings.TrimSpace(r.FormValue("claim_key"))
	if err := h.App.Claims.DeleteUserClaim(userID, key); err == nil {
		audit.LogSuccess("admin.claims.user.delete", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"target_type":    "user_oidc_claim",
			"target_id":      int64(userID),
			"claim_key":      key,
		})
	}
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/claims?success=deleted")
}

// UserProjectClaimUpsert sets or updates a project-scoped custom OIDC claim
// for a user. Both the user's org and the project must be in the actor's
// scope, and the user must already be assigned to the project (so we don't
// quietly create floating claims for unrelated user/project pairs).
func (h *AdminHandler) UserProjectClaimUpsert(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	userUUID := chi.URLParam(r, "userUuid")
	projectUUID := chi.URLParam(r, "projectUuid")
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.claims.project.upsert"})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=csrf")
		return
	}

	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var userID, projectID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &targetOrgUUID)
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid = ?`, projectUUID).Scan(&projectID)
	if userID == 0 || projectID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// User must already belong to the project we're scoping the claim to;
	// otherwise the claim would never be reachable but would still occupy
	// a row.
	var assigned int
	h.DB.QueryRow(`SELECT 1 FROM user_project_roles WHERE user_id=? AND project_id=? LIMIT 1`,
		userID, projectID).Scan(&assigned)
	if assigned != 1 {
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=not_assigned")
		return
	}

	key := strings.TrimSpace(r.FormValue("claim_key"))
	value := r.FormValue("claim_value")
	if err := h.App.Claims.SetProjectClaim(userID, projectID, key, value); err != nil {
		audit.LogFail("admin.claims.project.upsert.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"project_id":     projectID,
			"claim_key":      key,
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=invalid")
		return
	}
	audit.LogSuccess("admin.claims.project.upsert", service.AuditMeta{
		"actor_user_id":  actorID,
		"target_user_id": userID,
		"project_id":     projectID,
		"project_uuid":   projectUUID,
		"target_type":    "user_project_oidc_claim",
		"target_id":      int64(userID),
		"claim_key":      key,
	})
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/claims?success=updated")
}

// UserProjectClaimDelete removes a project-scoped claim.
func (h *AdminHandler) UserProjectClaimDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_users") {
		return
	}
	scope := h.scopeFor(r)
	userUUID := chi.URLParam(r, "userUuid")
	projectUUID := chi.URLParam(r, "projectUuid")
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/users/"+userUUID+"/claims?error=csrf")
		return
	}

	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var userID, projectID int
	var targetOrgUUID sql.NullString
	h.DB.QueryRow(`SELECT u.id, o.uuid FROM users u
	               LEFT JOIN organizations o ON o.id = u.organization_id
	               WHERE u.uuid = ?`, userUUID).Scan(&userID, &targetOrgUUID)
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid = ?`, projectUUID).Scan(&projectID)
	if userID == 0 || projectID == 0 {
		http.NotFound(w, r)
		return
	}
	if !h.actorCanReachUser(scope, userID, targetOrgUUID.String) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	key := strings.TrimSpace(r.FormValue("claim_key"))
	if err := h.App.Claims.DeleteProjectClaim(userID, projectID, key); err == nil {
		audit.LogSuccess("admin.claims.project.delete", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_user_id": userID,
			"project_id":     projectID,
			"project_uuid":   projectUUID,
			"target_type":    "user_project_oidc_claim",
			"target_id":      int64(userID),
			"claim_key":      key,
		})
	}
	sess.Save()
	redirect(w, r, "/admin/users/"+userUUID+"/claims?success=deleted")
}

// ─── Projects ─────────────────────────────────────────────────────────────────

// ProjectsList shows projects the actor can manage. Super-admins see all;
// scoped admins see only projects within their organisations.
func (h *AdminHandler) ProjectsList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_projects") {
		return
	}
	scope := h.scopeFor(r)

	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query(`SELECT p.id, p.uuid, p.name, p.status, o.name AS org_name
		                      FROM projects p
		                      LEFT JOIN organizations o ON o.id = p.organization_id
		                      ORDER BY p.created_at DESC`)
	} else if len(scope.ProjectIDs) > 0 {
		ph, args := inClausePlaceholders(scope.ProjectIDs)
		rows, _ = h.DB.Query(`SELECT p.id, p.uuid, p.name, p.status, o.name AS org_name
		                      FROM projects p
		                      LEFT JOIN organizations o ON o.id = p.organization_id
		                      WHERE p.id IN (`+ph+`)
		                      ORDER BY p.created_at DESC`, args...)
	}

	var projects []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var uid, name, status string
			var orgName sql.NullString
			rows.Scan(&id, &uid, &name, &status, &orgName)
			projects = append(projects, map[string]interface{}{
				"ID": id, "UUID": uid, "Name": name,
				"Status": status, "OrgName": orgName.String,
			})
		}
	}

	data := h.adminBaseData(w, r, "Projects")
	data["Projects"] = projects
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_projects")
	templates.AdminPage(w, "projects/list.html", data)
}

// ProjectCreate renders the new-project form. Org list is scoped to the actor.
func (h *AdminHandler) ProjectCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)

	var orgs []map[string]interface{}
	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query("SELECT uuid, name FROM organizations WHERE status='active' ORDER BY name")
	} else if len(scope.OrganizationIDs) > 0 {
		ph, args := inClausePlaceholders(scope.OrganizationIDs)
		rows, _ = h.DB.Query("SELECT uuid, name FROM organizations WHERE id IN ("+ph+") AND status='active' ORDER BY name", args...)
	}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var uid, name string
			rows.Scan(&uid, &name)
			orgs = append(orgs, map[string]interface{}{"UUID": uid, "Name": name})
		}
	}
	data := h.adminBaseData(w, r, "Create Project")
	data["Organizations"] = orgs
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/create.html", data)
}

// ProjectStore persists a new project under an actor-accessible org. Also
// seeds the default privilege levels (1=Owner ... 5=Viewer) for the project.
func (h *AdminHandler) ProjectStore(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	audit := getAudit(r)
	scope := h.scopeFor(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/create?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.project.create"})
		sess.Save()
		redirect(w, r, "/admin/projects/create?error=csrf")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	orgUUID := r.FormValue("organization_uuid")
	if name == "" {
		redirect(w, r, "/admin/projects/create?error=invalid")
		return
	}
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var orgID int
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)
	if orgID == 0 {
		redirect(w, r, "/admin/projects/create?error=invalid_org")
		return
	}

	projectUUID := uuid.NewString()
	res, err := h.DB.Exec("INSERT INTO projects (organization_id, uuid, name, status) VALUES (?,?,?,'active')", orgID, projectUUID, name)
	if err != nil {
		redirect(w, r, "/admin/projects/create?error=duplicate")
		return
	}
	projID, _ := res.LastInsertId()

	// Seed default privilege levels matching the PHP convention.
	defaultLevels := []struct {
		Level int
		Name  string
	}{
		{1, "Owner"}, {2, "Administrator"}, {3, "Editor"}, {4, "Member"}, {5, "Viewer"},
	}
	for _, lv := range defaultLevels {
		h.DB.Exec(`INSERT INTO project_privilege_levels (project_id, level, name) VALUES (?,?,?)`,
			projID, lv.Level, lv.Name)
	}

	audit.LogSuccess("admin.project.create", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_type":       "project",
		"target_id":         projID,
		"target_project_id": projID,
		"project_uuid":      projectUUID,
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"?success=created")
}

// ProjectDetail renders a project's profile + client / privilege summaries.
func (h *AdminHandler) ProjectDetail(w http.ResponseWriter, r *http.Request) {
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

	var id int
	var name, status string
	var orgName, orgUUID sql.NullString
	err := h.DB.QueryRow(`SELECT p.id, p.name, p.status, o.name, o.uuid
	                     FROM projects p
	                     LEFT JOIN organizations o ON o.id = p.organization_id
	                     WHERE p.uuid = ?`, projectUUID).Scan(&id, &name, &status, &orgName, &orgUUID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var clientCount, assignmentCount, privilegeCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM oauth_clients WHERE project_id=?", id).Scan(&clientCount)
	h.DB.QueryRow("SELECT COUNT(*) FROM user_project_roles WHERE project_id=?", id).Scan(&assignmentCount)
	h.DB.QueryRow("SELECT COUNT(*) FROM project_privilege_levels WHERE project_id=?", id).Scan(&privilegeCount)

	project := map[string]interface{}{
		"ID": id, "UUID": projectUUID, "Name": name,
		"Status": status, "OrgName": orgName.String, "OrgUUID": orgUUID.String,
		"ClientCount":     clientCount,
		"AssignmentCount": assignmentCount,
		"PrivilegeCount":  privilegeCount,
	}

	data := h.adminBaseData(w, r, "Project: "+name)
	data["Project"] = project
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_projects")
	data["CanDirectStatus"] = security.HasCapability(scope.AdminRole, "change_project_status_direct")
	data["CanDirectSettings"] = security.HasCapability(scope.AdminRole, "update_project_settings_direct")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/detail.html", data)
}

// ProjectUpdate updates a project's name/status. Both are gated by the
// matching *_direct capability; otherwise the change is enqueued as an
// approval request bound to the project.
func (h *AdminHandler) ProjectUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	projectUUID := chi.URLParam(r, "projectUuid")
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
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.project.update"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"?error=csrf")
		return
	}

	var projectID int
	var currentName, currentStatus string
	h.DB.QueryRow("SELECT id, name, status FROM projects WHERE uuid=?", projectUUID).Scan(&projectID, &currentName, &currentStatus)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	newName := strings.TrimSpace(r.FormValue("name"))
	if newName == "" {
		newName = currentName
	}
	newStatus := r.FormValue("status")
	if newStatus != "active" && newStatus != "disabled" {
		newStatus = currentStatus
	}

	current := security.ProjectSettings{Name: currentName, Status: currentStatus}
	requested := security.ProjectSettings{Name: newName, Status: newStatus}

	canSettings := security.HasCapability(scope.AdminRole, "update_project_settings_direct")
	canStatus := security.HasCapability(scope.AdminRole, "change_project_status_direct")
	canDirect := canSettings && (newStatus == currentStatus || canStatus)

	if security.ShouldRequireProjectSettingsApproval(canDirect, current, requested) {
		payload := map[string]interface{}{
			"target_type":    "project",
			"project_uuid":   projectUUID,
			"project_id":     projectID,
			"current_name":   currentName,
			"current_status": currentStatus,
			"new_name":       newName,
			"new_status":     newStatus,
			"requested_at":   time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("project.update", payload, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/projects/"+projectUUID+"?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":     actorID,
			"target_project_id": projectID,
			"project_id":        projectID,
			"target_type":       "approval_request",
			"target_id":         id,
			"action_type":       "project.update",
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"?success=pending_approval")
		return
	}

	h.DB.Exec("UPDATE projects SET name=?, status=? WHERE id=?", newName, newStatus, projectID)
	audit.LogSuccess("admin.project.update", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_type":       "project",
		"target_id":         int64(projectID),
		"target_project_id": projectID,
		"project_id":        projectID,
		"new_name":          newName,
		"new_status":        newStatus,
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"?success=updated")
}

// ─── Privilege Levels ─────────────────────────────────────────────────────────

// PrivilegeLevels lists a project's privilege rungs and the seat counts.
func (h *AdminHandler) PrivilegeLevels(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_privileges") {
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
	h.DB.QueryRow("SELECT id, name FROM projects WHERE uuid=?", projectUUID).Scan(&projectID, &projectName)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	rows, _ := h.DB.Query(`SELECT ppl.id, ppl.level, ppl.name,
	                            (SELECT COUNT(*) FROM user_project_roles upr
	                             WHERE upr.project_id = ppl.project_id AND upr.privilege_level = ppl.level) AS seat_count
	                      FROM project_privilege_levels ppl
	                      WHERE ppl.project_id = ?
	                      ORDER BY ppl.level`, projectID)
	var levels []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var lid, level, seatCount int
			var name string
			rows.Scan(&lid, &level, &name, &seatCount)
			levels = append(levels, map[string]interface{}{
				"ID": lid, "Level": level, "Name": name,
				"Label":     service.ResolvePrivilegeLabel(level, name),
				"SeatCount": seatCount,
			})
		}
	}

	data := h.adminBaseData(w, r, "Privilege Levels")
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName, "ID": projectID}
	data["Levels"] = levels
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_privileges")
	data["CanDirectDelete"] = security.HasCapability(scope.AdminRole, "delete_privilege_direct")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/privileges.html", data)
}

// PrivilegeLevelCreate adds a new rung to the project's privilege ladder.
func (h *AdminHandler) PrivilegeLevelCreate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_privileges") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.privilege_level.create"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=csrf")
		return
	}

	var projectID int
	h.DB.QueryRow("SELECT id FROM projects WHERE uuid=?", projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	level, _ := strconv.Atoi(r.FormValue("level"))
	name := strings.TrimSpace(r.FormValue("name"))
	if level <= 0 || name == "" {
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=invalid")
		return
	}

	res, err := h.DB.Exec("INSERT INTO project_privilege_levels (project_id, level, name) VALUES (?,?,?)", projectID, level, name)
	if err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=duplicate")
		return
	}
	newID, _ := res.LastInsertId()
	audit.LogSuccess("admin.privilege_level.create", service.AuditMeta{
		"actor_user_id":      actorID,
		"target_project_id":  projectID,
		"privilege_level_id": newID,
		"privilege_level":    level,
		"target_type":        "privilege_level",
		"target_id":          newID,
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?success=created")
}

// PrivilegeLevelUpdate renames a privilege level.
func (h *AdminHandler) PrivilegeLevelUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_privileges") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	levelID, _ := strconv.Atoi(chi.URLParam(r, "id"))

	var projectID int
	var projectUUID string
	h.DB.QueryRow(`SELECT p.id, p.uuid FROM projects p JOIN project_privilege_levels ppl ON ppl.project_id=p.id WHERE ppl.id=?`, levelID).Scan(&projectID, &projectUUID)
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.privilege_level.update"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=csrf")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name != "" {
		h.DB.Exec("UPDATE project_privilege_levels SET name=? WHERE id=?", name, levelID)
	}
	audit.LogSuccess("admin.privilege_level.update", service.AuditMeta{
		"actor_user_id":      actorID,
		"target_project_id":  projectID,
		"privilege_level_id": levelID,
		"target_type":        "privilege_level",
		"target_id":          int64(levelID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?success=updated")
}

// PrivilegeLevelDelete removes a rung. Requires delete_privilege_direct;
// otherwise the deletion is enqueued for approval.
func (h *AdminHandler) PrivilegeLevelDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_privileges") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	levelID, _ := strconv.Atoi(chi.URLParam(r, "id"))

	var projectID int
	var projectUUID string
	var levelNum int
	var levelName string
	h.DB.QueryRow(`SELECT p.id, p.uuid, ppl.level, ppl.name
	               FROM projects p JOIN project_privilege_levels ppl ON ppl.project_id=p.id
	               WHERE ppl.id=?`, levelID).Scan(&projectID, &projectUUID, &levelNum, &levelName)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.privilege_level.delete"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=csrf")
		return
	}

	canDirect := h.canActorActDirectly(r, "delete_privilege_direct")
	if !canDirect {
		payload := map[string]interface{}{
			"target_type":        "privilege_level",
			"project_uuid":       projectUUID,
			"project_id":         projectID,
			"privilege_level_id": levelID,
			"privilege_level":    levelNum,
			"privilege_name":     levelName,
			"requested_at":       time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("privilege_level.delete", payload, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":      actorID,
			"target_project_id":  projectID,
			"privilege_level_id": levelID,
			"target_type":        "approval_request",
			"target_id":          id,
			"action_type":        "privilege_level.delete",
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?success=pending_approval")
		return
	}

	h.DB.Exec("DELETE FROM project_privilege_levels WHERE id=?", levelID)
	audit.LogSuccess("admin.privilege_level.delete", service.AuditMeta{
		"actor_user_id":      actorID,
		"target_project_id":  projectID,
		"privilege_level_id": levelID,
		"target_type":        "privilege_level",
		"target_id":          int64(levelID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/privileges?success=deleted")
}

// ─── Assignments ──────────────────────────────────────────────────────────────
//
// All assignment mutations (create / update / delete) require approval unless
// the actor holds assignment_mutations_direct.

// ProjectAssignments lists current user-project role assignments alongside
// the available privilege levels and the pool of users eligible to be added.
func (h *AdminHandler) ProjectAssignments(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_assignments") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var projectID, orgID int
	var projectName string
	h.DB.QueryRow("SELECT id, name, organization_id FROM projects WHERE uuid=?", projectUUID).Scan(&projectID, &projectName, &orgID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	rows, _ := h.DB.Query(`SELECT upr.id, u.uuid, u.display_label, upr.privilege_level, COALESCE(ppl.name, '') AS priv_name
		FROM user_project_roles upr
		JOIN users u ON u.id=upr.user_id
		LEFT JOIN project_privilege_levels ppl ON ppl.project_id=upr.project_id AND ppl.level=upr.privilege_level
		WHERE upr.project_id=? ORDER BY u.display_label`, projectID)
	var assignments []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, level int
			var userUUID, userLabel, privName string
			rows.Scan(&id, &userUUID, &userLabel, &level, &privName)
			assignments = append(assignments, map[string]interface{}{
				"ID":             id,
				"UserUUID":       userUUID,
				"UserLabel":      userLabel,
				"PrivilegeLevel": level,
				"PrivilegeName":  privName,
				"PrivilegeLabel": service.ResolvePrivilegeLabel(level, privName),
			})
		}
	}

	levels, _ := h.DB.Query("SELECT level, name FROM project_privilege_levels WHERE project_id=? ORDER BY level", projectID)
	var privLevels []map[string]interface{}
	if levels != nil {
		defer levels.Close()
		for levels.Next() {
			var level int
			var name string
			levels.Scan(&level, &name)
			privLevels = append(privLevels, map[string]interface{}{
				"Level": level,
				"Name":  name,
				"Label": service.ResolvePrivilegeLabel(level, name),
			})
		}
	}

	// Eligible-user pool: users in the same organisation as the project
	// who are not already assigned to it.
	urows, _ := h.DB.Query(`SELECT u.uuid, u.display_label
	                        FROM users u
	                        WHERE u.organization_id = ? AND u.status='active'
	                          AND u.id NOT IN (SELECT user_id FROM user_project_roles WHERE project_id=?)
	                        ORDER BY u.display_label`, orgID, projectID)
	var users []map[string]interface{}
	if urows != nil {
		defer urows.Close()
		for urows.Next() {
			var uuid, label string
			urows.Scan(&uuid, &label)
			users = append(users, map[string]interface{}{"UUID": uuid, "Label": label})
		}
	}

	data := h.adminBaseData(w, r, "Assignments")
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName, "ID": projectID}
	data["Assignments"] = assignments
	data["PrivilegeLevels"] = privLevels
	data["EligibleUsers"] = users
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_assignments")
	data["CanDirect"] = security.HasCapability(scope.AdminRole, "assignment_mutations_direct")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/assignments.html", data)
}

// AssignmentCreate adds a user to a project at a chosen privilege level.
// Routed through approval unless the actor holds assignment_mutations_direct.
func (h *AdminHandler) AssignmentCreate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_assignments") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.assignment.create"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=csrf")
		return
	}

	var projectID int
	h.DB.QueryRow("SELECT id FROM projects WHERE uuid=?", projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	userUUID := r.FormValue("user_uuid")
	level, _ := strconv.Atoi(r.FormValue("privilege_level"))
	var userID int
	h.DB.QueryRow("SELECT id FROM users WHERE uuid=?", userUUID).Scan(&userID)
	if userID == 0 || level <= 0 {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=invalid")
		return
	}

	canDirect := h.canActorActDirectly(r, "assignment_mutations_direct")
	if security.ShouldRequireAssignmentApproval(canDirect) {
		payload := map[string]interface{}{
			"target_type":      "assignment",
			"operation":        "create",
			"project_uuid":     projectUUID,
			"project_id":       projectID,
			"target_user_uuid": userUUID,
			"target_user_id":   userID,
			"privilege_level":  level,
			"requested_at":     time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("assignment.create", payload, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":     actorID,
			"target_project_id": projectID,
			"target_user_id":    userID,
			"target_type":       "approval_request",
			"target_id":         id,
			"action_type":       "assignment.create",
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=pending_approval")
		return
	}

	res, err := h.DB.Exec("INSERT INTO user_project_roles (user_id, project_id, privilege_level) VALUES (?,?,?)", userID, projectID, level)
	if err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=duplicate")
		return
	}
	newID, _ := res.LastInsertId()
	audit.LogSuccess("admin.assignment.create", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_user_id":    userID,
		"target_project_id": projectID,
		"project_id":        projectID,
		"privilege_level":   level,
		"target_type":       "assignment",
		"target_id":         newID,
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=created")
}

// AssignmentUpdate changes a user's privilege level on a project.
func (h *AdminHandler) AssignmentUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_assignments") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	assignmentID, _ := strconv.Atoi(chi.URLParam(r, "id"))

	var projectID, userID, currentLevel int
	var projectUUID string
	h.DB.QueryRow(`SELECT p.id, p.uuid, upr.user_id, upr.privilege_level
	               FROM projects p JOIN user_project_roles upr ON upr.project_id=p.id
	               WHERE upr.id=?`, assignmentID).Scan(&projectID, &projectUUID, &userID, &currentLevel)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.assignment.update"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=csrf")
		return
	}

	level, _ := strconv.Atoi(r.FormValue("privilege_level"))
	if level <= 0 || level == currentLevel {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=invalid")
		return
	}

	canDirect := h.canActorActDirectly(r, "assignment_mutations_direct")
	if security.ShouldRequireAssignmentApproval(canDirect) {
		payload := map[string]interface{}{
			"target_type":    "assignment",
			"operation":      "update",
			"assignment_id":  assignmentID,
			"project_uuid":   projectUUID,
			"project_id":     projectID,
			"target_user_id": userID,
			"current_level":  currentLevel,
			"new_level":      level,
			"requested_at":   time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("assignment.update", payload, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":     actorID,
			"target_project_id": projectID,
			"target_user_id":    userID,
			"target_type":       "approval_request",
			"target_id":         id,
			"action_type":       "assignment.update",
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=pending_approval")
		return
	}

	h.DB.Exec("UPDATE user_project_roles SET privilege_level=? WHERE id=?", level, assignmentID)
	audit.LogSuccess("admin.assignment.update", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_user_id":    userID,
		"target_project_id": projectID,
		"privilege_level":   level,
		"target_type":       "assignment",
		"target_id":         int64(assignmentID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=updated")
}

// AssignmentDelete removes a user-project assignment.
func (h *AdminHandler) AssignmentDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_assignments") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	assignmentID, _ := strconv.Atoi(chi.URLParam(r, "id"))

	var projectID, userID, level int
	var projectUUID string
	h.DB.QueryRow(`SELECT p.id, p.uuid, upr.user_id, upr.privilege_level
	               FROM projects p JOIN user_project_roles upr ON upr.project_id=p.id
	               WHERE upr.id=?`, assignmentID).Scan(&projectID, &projectUUID, &userID, &level)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.assignment.delete"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=csrf")
		return
	}

	canDirect := h.canActorActDirectly(r, "assignment_mutations_direct")
	if security.ShouldRequireAssignmentApproval(canDirect) {
		payload := map[string]interface{}{
			"target_type":     "assignment",
			"operation":       "delete",
			"assignment_id":   assignmentID,
			"project_uuid":    projectUUID,
			"project_id":      projectID,
			"target_user_id":  userID,
			"privilege_level": level,
			"requested_at":    time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("assignment.delete", payload, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":     actorID,
			"target_project_id": projectID,
			"target_user_id":    userID,
			"target_type":       "approval_request",
			"target_id":         id,
			"action_type":       "assignment.delete",
		})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=pending_approval")
		return
	}

	h.DB.Exec("DELETE FROM user_project_roles WHERE id=?", assignmentID)
	audit.LogSuccess("admin.assignment.delete", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_user_id":    userID,
		"target_project_id": projectID,
		"target_type":       "assignment",
		"target_id":         int64(assignmentID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/assignments?success=deleted")
}

// ─── OAuth Clients ────────────────────────────────────────────────────────────

// ClientsList shows OAuth clients registered to a project.
func (h *AdminHandler) ClientsList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_clients") {
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
	h.DB.QueryRow("SELECT id, name FROM projects WHERE uuid=?", projectUUID).Scan(&projectID, &projectName)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	rows, _ := h.DB.Query(`SELECT client_id, name, status, client_secret_hash IS NOT NULL AS confidential, created_at
	                      FROM oauth_clients WHERE project_id=? ORDER BY created_at DESC`, projectID)
	var clients []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var pubID, name, status string
			var confidential bool
			var createdAt time.Time
			rows.Scan(&pubID, &name, &status, &confidential, &createdAt)
			clients = append(clients, map[string]interface{}{
				"PublicID":     pubID,
				"Name":         name,
				"Status":       status,
				"Confidential": confidential,
				"CreatedAt":    createdAt,
			})
		}
	}

	data := h.adminBaseData(w, r, "OAuth Clients")
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName, "ID": projectID}
	data["Clients"] = clients
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_clients")
	templates.AdminPage(w, "clients/list.html", data)
}

// ClientCreate renders the new OAuth client form.
func (h *AdminHandler) ClientCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_clients") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var projectName string
	h.DB.QueryRow("SELECT name FROM projects WHERE uuid=?", projectUUID).Scan(&projectName)
	data := h.adminBaseData(w, r, "Create OAuth Client")
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName}
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "clients/create.html", data)
}

// ClientStore creates a new OAuth client. For confidential clients a fresh
// secret is generated and shown once on the detail page.
func (h *AdminHandler) ClientStore(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_clients") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/clients/create?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.client.create"})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/clients/create?error=csrf")
		return
	}

	var projectID int
	h.DB.QueryRow("SELECT id FROM projects WHERE uuid=?", projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirect(w, r, "/admin/projects/"+projectUUID+"/clients/create?error=invalid")
		return
	}

	clientPublicID := uuid.NewString()
	clientType := r.FormValue("client_type")
	confidential := clientType != "public"

	var clientSecret string
	var secretHashVal sql.NullString
	if confidential {
		clientSecret = hexToken(32)
		secretHashVal = sql.NullString{String: hashSecret(clientSecret), Valid: true}
	}

	redirectURIList := splitLines(r.FormValue("redirect_uris"))
	grantList := splitLines(r.FormValue("grants"))
	if len(grantList) == 0 {
		grantList = []string{"authorization_code", "refresh_token"}
	}
	scopeList := splitLines(r.FormValue("scopes"))

	redirectURIs, _ := json.Marshal(redirectURIList)
	grants, _ := json.Marshal(grantList)
	scopes, _ := json.Marshal(scopeList)

	accessTokenType := r.FormValue("access_token_type")
	if accessTokenType != "jwt" && accessTokenType != "opaque" {
		accessTokenType = "jwt"
	}
	accessLifetime, _ := strconv.Atoi(r.FormValue("access_token_lifetime"))
	if accessLifetime <= 0 {
		accessLifetime = 3600
	}
	refreshLifetime, _ := strconv.Atoi(r.FormValue("refresh_token_lifetime"))
	if refreshLifetime <= 0 {
		refreshLifetime = 2592000
	}
	oidcEnabled := r.FormValue("oidc_enabled") == "1"

	res, err := h.DB.Exec(`INSERT INTO oauth_clients
		(project_id, client_id, client_secret_hash, name, redirect_uris, grants, scopes,
		 pkce_required, access_token_type, access_token_lifetime, refresh_token_lifetime, oidc_enabled, status)
		VALUES (?,?,?,?,?,?,?,1,?,?,?,?,'active')`,
		projectID, clientPublicID, secretHashVal, name, string(redirectURIs), string(grants), string(scopes),
		accessTokenType, accessLifetime, refreshLifetime, boolToInt(oidcEnabled))
	if err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/clients/create?error=failed")
		return
	}
	newID, _ := res.LastInsertId()
	audit.LogSuccess("admin.client.create", service.AuditMeta{
		"actor_user_id":          actorID,
		"target_project_id":      projectID,
		"project_id":             projectID,
		"oauth_client_id":        newID,
		"oauth_client_public_id": clientPublicID,
		"target_type":            "oauth_client",
		"target_id":              newID,
		"client_confidential":    confidential,
	})
	sess.Save()
	redirectURL := "/admin/clients/" + clientPublicID + "?success=created"
	if clientSecret != "" {
		redirectURL += "&secret=" + clientSecret
	}
	redirect(w, r, redirectURL)
}

// ClientDetail loads the full client record for editing.
func (h *AdminHandler) ClientDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_clients") {
		return
	}
	scope := h.scopeFor(r)
	clientPublicID := chi.URLParam(r, "clientPublicId")

	var id, projectID, accessLifetime, refreshLifetime int
	var name, status, redirectURIs, grants, scopes, accessTokenType, projectUUID, projectName string
	var secretHash sql.NullString
	var oidcEnabled bool
	err := h.DB.QueryRow(`SELECT c.id, c.project_id, c.client_secret_hash, c.name, c.redirect_uris,
		                       c.grants, c.scopes, c.access_token_type, c.access_token_lifetime,
		                       c.refresh_token_lifetime, c.oidc_enabled, c.status,
		                       p.uuid, p.name
	                     FROM oauth_clients c
	                     JOIN projects p ON p.id = c.project_id
	                     WHERE c.client_id=?`, clientPublicID).
		Scan(&id, &projectID, &secretHash, &name, &redirectURIs, &grants, &scopes,
			&accessTokenType, &accessLifetime, &refreshLifetime, &oidcEnabled, &status,
			&projectUUID, &projectName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var redirectList, grantList, scopeList []string
	json.Unmarshal([]byte(redirectURIs), &redirectList)
	json.Unmarshal([]byte(grants), &grantList)
	json.Unmarshal([]byte(scopes), &scopeList)

	client := map[string]interface{}{
		"ID":                   id,
		"PublicID":             clientPublicID,
		"ProjectUUID":          projectUUID,
		"ProjectName":          projectName,
		"Name":                 name,
		"Confidential":         secretHash.Valid,
		"RedirectURIs":         redirectList,
		"Grants":               grantList,
		"Scopes":               scopeList,
		"AccessTokenType":      accessTokenType,
		"AccessTokenLifetime":  accessLifetime,
		"RefreshTokenLifetime": refreshLifetime,
		"OIDCEnabled":          oidcEnabled,
		"Status":               status,
	}

	data := h.adminBaseData(w, r, "Client: "+name)
	data["Client"] = client
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_clients")
	data["CanDirectStatus"] = security.HasCapability(scope.AdminRole, "change_client_status_direct")
	data["CanDirectSettings"] = security.HasCapability(scope.AdminRole, "update_client_settings_direct")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	data["NewSecret"] = r.URL.Query().Get("secret")
	templates.AdminPage(w, "clients/detail.html", data)
}

// ClientUpdate persists a client edit. Routes through approval if the actor
// lacks the *_direct capability AND the requested change touches gated fields.
func (h *AdminHandler) ClientUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_clients") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	clientPublicID := chi.URLParam(r, "clientPublicId")

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/clients/"+clientPublicID+"?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.client.update"})
		sess.Save()
		redirect(w, r, "/admin/clients/"+clientPublicID+"?error=csrf")
		return
	}

	var clientID, projectID, currentAccessLifetime, currentRefreshLifetime int
	var currentName, currentStatus, currentRedirectURIs, currentScopes, currentAccessTokenType string
	var currentOIDC bool
	err := h.DB.QueryRow(`SELECT id, project_id, name, status, redirect_uris, scopes,
		                       access_token_type, access_token_lifetime, refresh_token_lifetime, oidc_enabled
		                     FROM oauth_clients WHERE client_id=?`, clientPublicID).
		Scan(&clientID, &projectID, &currentName, &currentStatus, &currentRedirectURIs, &currentScopes,
			&currentAccessTokenType, &currentAccessLifetime, &currentRefreshLifetime, &currentOIDC)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !scope.CanAccessProjectID(projectID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	newName := strings.TrimSpace(r.FormValue("name"))
	if newName == "" {
		newName = currentName
	}
	newStatus := r.FormValue("status")
	if newStatus != "active" && newStatus != "disabled" {
		newStatus = currentStatus
	}
	newRedirectURIs := splitLines(r.FormValue("redirect_uris"))
	newScopes := splitLines(r.FormValue("scopes"))
	newAccessTokenType := r.FormValue("access_token_type")
	if newAccessTokenType != "jwt" && newAccessTokenType != "opaque" {
		newAccessTokenType = currentAccessTokenType
	}
	newAccessLifetime, _ := strconv.Atoi(r.FormValue("access_token_lifetime"))
	if newAccessLifetime <= 0 {
		newAccessLifetime = currentAccessLifetime
	}
	newRefreshLifetime, _ := strconv.Atoi(r.FormValue("refresh_token_lifetime"))
	if newRefreshLifetime <= 0 {
		newRefreshLifetime = currentRefreshLifetime
	}
	newOIDC := r.FormValue("oidc_enabled") == "1"

	var currentRedirectList, currentScopeList []string
	json.Unmarshal([]byte(currentRedirectURIs), &currentRedirectList)
	json.Unmarshal([]byte(currentScopes), &currentScopeList)

	current := security.ClientSettings{
		Name: currentName, Status: currentStatus,
		RedirectURIs: currentRedirectList, Scopes: currentScopeList,
		AccessTokenType: currentAccessTokenType, AccessTokenLifetime: currentAccessLifetime,
		RefreshTokenLifetime: currentRefreshLifetime, OIDCEnabled: currentOIDC,
	}
	requested := security.ClientSettings{
		Name: newName, Status: newStatus,
		RedirectURIs: newRedirectURIs, Scopes: newScopes,
		AccessTokenType: newAccessTokenType, AccessTokenLifetime: newAccessLifetime,
		RefreshTokenLifetime: newRefreshLifetime, OIDCEnabled: newOIDC,
	}

	canSettings := security.HasCapability(scope.AdminRole, "update_client_settings_direct")
	canStatus := security.HasCapability(scope.AdminRole, "change_client_status_direct")
	canDirect := canSettings && (newStatus == currentStatus || canStatus)

	if security.ShouldRequireClientSettingsApproval(canDirect, current, requested) {
		payloadBytes := map[string]interface{}{
			"target_type":            "oauth_client",
			"oauth_client_public_id": clientPublicID,
			"oauth_client_id":        clientID,
			"project_id":             projectID,
			"current":                current,
			"requested":              requested,
			"requested_at":           time.Now().UTC().Format(time.RFC3339),
		}
		id, err := h.App.Approval.Create("client.update", payloadBytes, actorID, &projectID)
		if err != nil {
			redirect(w, r, "/admin/clients/"+clientPublicID+"?error=approval_failed")
			return
		}
		audit.LogInfo("admin.approval.enqueued", service.AuditMeta{
			"actor_user_id":          actorID,
			"oauth_client_id":        clientID,
			"oauth_client_public_id": clientPublicID,
			"project_id":             projectID,
			"target_type":            "approval_request",
			"target_id":              id,
			"action_type":            "client.update",
		})
		sess.Save()
		redirect(w, r, "/admin/clients/"+clientPublicID+"?success=pending_approval")
		return
	}

	redirectsJSON, _ := json.Marshal(newRedirectURIs)
	scopesJSON, _ := json.Marshal(newScopes)
	h.DB.Exec(`UPDATE oauth_clients SET name=?, status=?, redirect_uris=?, scopes=?,
		         access_token_type=?, access_token_lifetime=?, refresh_token_lifetime=?, oidc_enabled=?
		     WHERE id=?`,
		newName, newStatus, string(redirectsJSON), string(scopesJSON),
		newAccessTokenType, newAccessLifetime, newRefreshLifetime, boolToInt(newOIDC), clientID)

	audit.LogSuccess("admin.client.update", service.AuditMeta{
		"actor_user_id":          actorID,
		"oauth_client_id":        clientID,
		"oauth_client_public_id": clientPublicID,
		"project_id":             projectID,
		"target_type":            "oauth_client",
		"target_id":              int64(clientID),
	})
	sess.Save()
	redirect(w, r, "/admin/clients/"+clientPublicID+"?success=updated")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

// AuditLog shows the searchable, scope-aware audit feed. Filters supported:
// event_type, outcome, actor_user_uuid, project_uuid, target_type, date_from,
// date_to, correlation_id. Pagination uses LIMIT/OFFSET.
func (h *AdminHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_audit") {
		return
	}
	scope := h.scopeFor(r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50
	offset := (page - 1) * pageSize

	conds := []string{}
	args := []interface{}{}
	addCond := func(cond string, val interface{}) {
		conds = append(conds, cond)
		args = append(args, val)
	}

	if v := r.URL.Query().Get("event_type"); v != "" {
		addCond("event_type LIKE ?", "%"+v+"%")
	}
	if v := r.URL.Query().Get("outcome"); v != "" && (v == "success" || v == "fail" || v == "info") {
		addCond("outcome = ?", v)
	}
	if v := r.URL.Query().Get("actor_user_uuid"); v != "" {
		addCond("actor_user_uuid = ?", v)
	}
	if v := r.URL.Query().Get("project_uuid"); v != "" {
		addCond("project_uuid = ?", v)
	}
	if v := r.URL.Query().Get("target_type"); v != "" {
		addCond("target_type = ?", v)
	}
	if v := r.URL.Query().Get("correlation_id"); v != "" {
		addCond("correlation_id = ?", v)
	}
	if v := r.URL.Query().Get("date_from"); v != "" {
		addCond("created_at >= ?", v)
	}
	if v := r.URL.Query().Get("date_to"); v != "" {
		addCond("created_at <= ?", v)
	}

	// Scope filtering: non-super-admins only see entries tied to their projects
	// (or entries with no project_id, e.g. system events).
	if !scope.IsSuperAdmin {
		if len(scope.ProjectIDs) == 0 {
			conds = append(conds, "1=0")
		} else {
			ph, ids := inClausePlaceholders(scope.ProjectIDs)
			conds = append(conds, "(project_id IS NULL OR project_id IN ("+ph+"))")
			args = append(args, ids...)
		}
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var totalCount int
	h.DB.QueryRow(`SELECT COUNT(*) FROM audit_log `+where, args...).Scan(&totalCount)

	listQ := `SELECT id, event_type, outcome, COALESCE(message, ''),
	                 actor_user_uuid, project_uuid, target_type, target_id,
	                 ip_address, COALESCE(correlation_id, ''),
	                 COALESCE(metadata_json, ''), created_at
	          FROM audit_log ` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)
	rows, _ := h.DB.Query(listQ, args...)

	var entries []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var eventT, out, message, ip, corr, metaJSON string
			var actorUUID, projectUUID, targetType sql.NullString
			var targetID sql.NullInt64
			var createdAt time.Time
			rows.Scan(&id, &eventT, &out, &message, &actorUUID, &projectUUID, &targetType, &targetID, &ip, &corr, &metaJSON, &createdAt)
			entries = append(entries, map[string]interface{}{
				"ID":            id,
				"EventType":     eventT,
				"Outcome":       out,
				"Message":       message,
				"ActorUUID":     actorUUID.String,
				"ProjectUUID":   projectUUID.String,
				"TargetType":    targetType.String,
				"TargetID":      targetID.Int64,
				"IP":            ip,
				"CorrelationID": corr,
				"MetadataJSON":  metaJSON,
				"CreatedAt":     createdAt,
			})
		}
	}

	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	data := h.adminBaseData(w, r, "Audit Log")
	data["Entries"] = entries
	data["Page"] = page
	data["TotalPages"] = totalPages
	data["TotalCount"] = totalCount
	data["Filters"] = map[string]string{
		"event_type":      r.URL.Query().Get("event_type"),
		"outcome":         r.URL.Query().Get("outcome"),
		"actor_user_uuid": r.URL.Query().Get("actor_user_uuid"),
		"project_uuid":    r.URL.Query().Get("project_uuid"),
		"target_type":     r.URL.Query().Get("target_type"),
		"correlation_id":  r.URL.Query().Get("correlation_id"),
		"date_from":       r.URL.Query().Get("date_from"),
		"date_to":         r.URL.Query().Get("date_to"),
	}
	templates.AdminPage(w, "audit/log.html", data)
}

// AuditExport streams a CSV of the (scope-filtered) audit log followed by a
// MANIFEST.txt-style trailer with an HMAC over the body. The HMAC key comes
// from config.AuditExportSigningKey (or csrf_secret if unset) so the export
// can be verified later for tamper-evidence.
func (h *AdminHandler) AuditExport(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "view_audit") {
		return
	}
	scope := h.scopeFor(r)
	cfg := config.Get()

	// Build scope filter (same as AuditLog).
	conds := []string{}
	args := []interface{}{}
	if v := r.URL.Query().Get("event_type"); v != "" {
		conds = append(conds, "event_type LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if v := r.URL.Query().Get("outcome"); v != "" && (v == "success" || v == "fail" || v == "info") {
		conds = append(conds, "outcome = ?")
		args = append(args, v)
	}
	if v := r.URL.Query().Get("date_from"); v != "" {
		conds = append(conds, "created_at >= ?")
		args = append(args, v)
	}
	if v := r.URL.Query().Get("date_to"); v != "" {
		conds = append(conds, "created_at <= ?")
		args = append(args, v)
	}
	if !scope.IsSuperAdmin {
		if len(scope.ProjectIDs) == 0 {
			conds = append(conds, "1=0")
		} else {
			ph, ids := inClausePlaceholders(scope.ProjectIDs)
			conds = append(conds, "(project_id IS NULL OR project_id IN ("+ph+"))")
			args = append(args, ids...)
		}
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_export.csv")

	signingKey := cfg.AuditExportSignKey
	if signingKey == "" {
		signingKey = cfg.CSRFSecret
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	mw := io.MultiWriter(w, mac)

	header := "id,created_at,event_type,outcome,message,correlation_id,ip_address,user_agent,actor_user_uuid,project_uuid,organization_uuid,oauth_client_public_id,target_type,target_id,chain_prev_hash,chain_hash\n"
	mw.Write([]byte(header))

	rows, _ := h.DB.Query(`SELECT id, created_at, event_type, outcome, COALESCE(message, ''),
		                          COALESCE(correlation_id, ''), ip_address, COALESCE(user_agent, ''),
		                          actor_user_uuid, project_uuid, organization_uuid, oauth_client_public_id,
		                          target_type, target_id, chain_prev_hash, chain_hash
		                   FROM audit_log `+where+` ORDER BY id ASC LIMIT 250000`, args...)
	rowCount := 0
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var createdAt time.Time
			var eventT, outcome, message, corr, ip, ua string
			var actorUUID, projUUID, orgUUID, clientPub, targetType, prevHash, chainHash sql.NullString
			var targetID sql.NullInt64
			rows.Scan(&id, &createdAt, &eventT, &outcome, &message, &corr, &ip, &ua,
				&actorUUID, &projUUID, &orgUUID, &clientPub, &targetType, &targetID, &prevHash, &chainHash)
			line := fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				id, createdAt.UTC().Format(time.RFC3339), csvField(eventT), csvField(outcome), csvField(message),
				csvField(corr), csvField(ip), csvField(ua),
				csvField(actorUUID.String), csvField(projUUID.String), csvField(orgUUID.String),
				csvField(clientPub.String), csvField(targetType.String),
				csvField(fmt.Sprintf("%d", targetID.Int64)),
				csvField(prevHash.String), csvField(chainHash.String))
			mw.Write([]byte(line))
			rowCount++
		}
	}

	manifestLine := fmt.Sprintf("# manifest: rows=%d generated_at=%s hmac_sha256=%s\n",
		rowCount, time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(mac.Sum(nil)))
	w.Write([]byte(manifestLine))

	if audit := getAudit(r); audit != nil {
		audit.LogSuccess("admin.audit.export", service.AuditMeta{
			"actor_user_id": actorID,
			"row_count":     rowCount,
		})
	}
}

// csvField escapes a CSV value: doubles internal quotes and wraps in quotes
// if the value contains a comma, quote, or newline.
func csvField(s string) string {
	if !strings.ContainsAny(s, ",\"\n\r") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// ─── Organizations ────────────────────────────────────────────────────────────

// OrganizationsList shows organisations the actor can administer.
func (h *AdminHandler) OrganizationsList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_organizations") {
		return
	}
	scope := h.scopeFor(r)

	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query(`SELECT o.uuid, o.name, o.slug, o.status,
		                            COALESCE(u.display_label, '') AS admin_label,
		                            COALESCE(u.uuid, '') AS admin_uuid,
		                            (SELECT COUNT(*) FROM projects WHERE organization_id=o.id) AS project_count,
		                            (SELECT COUNT(*) FROM users WHERE organization_id=o.id) AS user_count
		                      FROM organizations o
		                      LEFT JOIN users u ON u.id = o.admin_user_id
		                      ORDER BY o.name`)
	} else if len(scope.OrganizationIDs) > 0 {
		ph, args := inClausePlaceholders(scope.OrganizationIDs)
		rows, _ = h.DB.Query(`SELECT o.uuid, o.name, o.slug, o.status,
		                            COALESCE(u.display_label, ''),
		                            COALESCE(u.uuid, ''),
		                            (SELECT COUNT(*) FROM projects WHERE organization_id=o.id),
		                            (SELECT COUNT(*) FROM users WHERE organization_id=o.id)
		                      FROM organizations o
		                      LEFT JOIN users u ON u.id = o.admin_user_id
		                      WHERE o.id IN (`+ph+`)
		                      ORDER BY o.name`, args...)
	}
	var orgs []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var uid, name, slug, status, adminLabel, adminUUID string
			var projectCount, userCount int
			rows.Scan(&uid, &name, &slug, &status, &adminLabel, &adminUUID, &projectCount, &userCount)
			orgs = append(orgs, map[string]interface{}{
				"UUID": uid, "Name": name, "Slug": slug, "Status": status,
				"AdminLabel": adminLabel, "AdminUUID": adminUUID,
				"ProjectCount": projectCount, "UserCount": userCount,
			})
		}
	}
	data := h.adminBaseData(w, r, "Organizations")
	data["Organizations"] = orgs
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_organizations")
	templates.AdminPage(w, "organizations/list.html", data)
}

// OrganizationStore creates a new organisation.
func (h *AdminHandler) OrganizationStore(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/organisations?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.org.create"})
		sess.Save()
		redirect(w, r, "/admin/organisations?error=csrf")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	slug := strings.TrimSpace(r.FormValue("slug"))
	if name == "" || slug == "" {
		redirect(w, r, "/admin/organisations?error=invalid")
		return
	}

	orgUUID := uuid.NewString()
	res, err := h.DB.Exec("INSERT INTO organizations (uuid, name, slug, status) VALUES (?,?,?,'active')", orgUUID, name, slug)
	if err != nil {
		redirect(w, r, "/admin/organisations?error=duplicate")
		return
	}
	orgID, _ := res.LastInsertId()
	audit.LogSuccess("admin.org.create", service.AuditMeta{
		"actor_user_id":     actorID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
		"target_type":       "organization",
		"target_id":         orgID,
	})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=created")
}

// OrganizationDetail shows the org profile, its admin, projects, and users.
func (h *AdminHandler) OrganizationDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_organizations") {
		return
	}
	scope := h.scopeFor(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
	if !scope.CanAccessOrganizationUUID(orgUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var id int
	var name, slug, status string
	var adminUserID sql.NullInt64
	err := h.DB.QueryRow("SELECT id, name, slug, status, admin_user_id FROM organizations WHERE uuid=?", orgUUID).Scan(&id, &name, &slug, &status, &adminUserID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var userCount, projectCount int64
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE organization_id=?", id).Scan(&userCount)
	h.DB.QueryRow("SELECT COUNT(*) FROM projects WHERE organization_id=?", id).Scan(&projectCount)

	var adminLabel, adminUUID string
	if adminUserID.Valid {
		h.DB.QueryRow("SELECT display_label, uuid FROM users WHERE id=?", adminUserID.Int64).Scan(&adminLabel, &adminUUID)
	}

	// Sample of recent projects + users for the detail page.
	var projects []map[string]interface{}
	if rows, _ := h.DB.Query("SELECT uuid, name, status FROM projects WHERE organization_id=? ORDER BY created_at DESC LIMIT 50", id); rows != nil {
		for rows.Next() {
			var puid, pname, pstatus string
			rows.Scan(&puid, &pname, &pstatus)
			projects = append(projects, map[string]interface{}{"UUID": puid, "Name": pname, "Status": pstatus})
		}
		rows.Close()
	}
	var users []map[string]interface{}
	if rows, _ := h.DB.Query("SELECT uuid, display_label, status FROM users WHERE organization_id=? ORDER BY created_at DESC LIMIT 50", id); rows != nil {
		for rows.Next() {
			var uuid, label, ustatus string
			rows.Scan(&uuid, &label, &ustatus)
			users = append(users, map[string]interface{}{"UUID": uuid, "DisplayLabel": label, "Status": ustatus})
		}
		rows.Close()
	}

	// Eligible candidates for "switch admin" — active users in the org.
	var candidates []map[string]interface{}
	if rows, _ := h.DB.Query(`SELECT uuid, display_label FROM users
	                          WHERE organization_id=? AND status='active'
	                          ORDER BY display_label`, id); rows != nil {
		for rows.Next() {
			var uuid, label string
			rows.Scan(&uuid, &label)
			candidates = append(candidates, map[string]interface{}{"UUID": uuid, "Label": label})
		}
		rows.Close()
	}

	data := h.adminBaseData(w, r, "Org: "+name)
	data["Org"] = map[string]interface{}{
		"UUID": orgUUID, "Name": name, "Slug": slug, "Status": status,
		"AdminLabel": adminLabel, "AdminUUID": adminUUID,
		"UserCount": userCount, "ProjectCount": projectCount,
	}
	data["Projects"] = projects
	data["Users"] = users
	data["AdminCandidates"] = candidates
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_organizations")
	data["CanSwitchAdmin"] = security.HasCapability(scope.AdminRole, "switch_organization_admin")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "organizations/detail.html", data)
}

// OrganizationUpdate updates name and status fields.
func (h *AdminHandler) OrganizationUpdate(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
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
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.org.update"})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}

	var orgID int
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)
	if orgID == 0 {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	status := r.FormValue("status")
	if name != "" {
		h.DB.Exec("UPDATE organizations SET name=? WHERE id=?", name, orgID)
	}
	if status == "active" || status == "disabled" {
		h.DB.Exec("UPDATE organizations SET status=? WHERE id=?", status, orgID)
	}
	audit.LogSuccess("admin.org.update", service.AuditMeta{
		"actor_user_id":     actorID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
		"target_type":       "organization",
		"target_id":         int64(orgID),
	})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=updated")
}

// ─── Admin Roles ──────────────────────────────────────────────────────────────

// AdminRoles lists every assigned admin role + their capability sets, plus
// a picker for adding new role assignments.
func (h *AdminHandler) AdminRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	roles, _ := h.App.AdminAuth.ListRoles()
	users, _ := h.DB.Query(`SELECT uuid, display_label FROM users
	                        WHERE status='active' ORDER BY display_label LIMIT 500`)
	var userList []map[string]interface{}
	if users != nil {
		defer users.Close()
		for users.Next() {
			var uid, label string
			users.Scan(&uid, &label)
			userList = append(userList, map[string]interface{}{"UUID": uid, "Label": label})
		}
	}

	roleCatalog := []map[string]interface{}{
		{"Role": security.RoleSuperAdmin, "Capabilities": security.CapabilitiesFor(security.RoleSuperAdmin)},
		{"Role": security.RoleOperator, "Capabilities": security.CapabilitiesFor(security.RoleOperator)},
		{"Role": security.RoleAuditor, "Capabilities": security.CapabilitiesFor(security.RoleAuditor)},
	}

	data := h.adminBaseData(w, r, "Admin Roles")
	data["Roles"] = roles
	data["Users"] = userList
	data["RoleCatalog"] = roleCatalog
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "roles.html", data)
}

// AdminRoleUpsert grants or updates a user's admin role.
func (h *AdminHandler) AdminRoleUpsert(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/roles?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.role.upsert"})
		sess.Save()
		redirect(w, r, "/admin/roles?error=csrf")
		return
	}

	userUUID := r.FormValue("user_uuid")
	role := r.FormValue("role")
	if userUUID == "" || (role != security.RoleSuperAdmin && role != security.RoleOperator && role != security.RoleAuditor) {
		redirect(w, r, "/admin/roles?error=invalid")
		return
	}

	var targetUserID int
	h.DB.QueryRow("SELECT id FROM users WHERE uuid=?", userUUID).Scan(&targetUserID)
	if targetUserID == 0 {
		redirect(w, r, "/admin/roles?error=user_not_found")
		return
	}

	if err := h.App.AdminAuth.UpsertRole(targetUserID, role); err != nil {
		redirect(w, r, "/admin/roles?error=update_failed")
		return
	}
	audit.LogSuccess("admin.role.upsert", service.AuditMeta{
		"actor_user_id":  actorID,
		"target_user_id": targetUserID,
		"role":           role,
		"target_type":    "admin_role",
		"target_id":      int64(targetUserID),
	})
	sess.Save()
	redirect(w, r, "/admin/roles?success=updated")
}

// AdminRoleRevoke removes a user's admin role assignment. The user keeps
// their organisation membership; only the elevated capability matrix is removed.
func (h *AdminHandler) AdminRoleRevoke(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_roles") {
		return
	}
	audit := getAudit(r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/roles?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.role.revoke"})
		sess.Save()
		redirect(w, r, "/admin/roles?error=csrf")
		return
	}

	targetUserID, _ := strconv.Atoi(chi.URLParam(r, "userId"))
	if err := h.App.AdminAuth.RevokeRole(targetUserID); err != nil {
		redirect(w, r, "/admin/roles?error=revoke_failed")
		return
	}
	audit.LogSuccess("admin.role.revoke", service.AuditMeta{
		"actor_user_id":  actorID,
		"target_user_id": targetUserID,
		"target_type":    "admin_role",
		"target_id":      int64(targetUserID),
	})
	sess.Save()
	redirect(w, r, "/admin/roles?success=revoked")
}

// ─── Approvals ────────────────────────────────────────────────────────────────

// ApprovalsList shows the queue with status / action_type / project filters.
// Visibility is scoped: actors with decide_approvals see everything, others
// only see their own requests + requests targeting projects they can access.
func (h *AdminHandler) ApprovalsList(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "view_approvals") {
		return
	}
	scope := h.scopeFor(r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50
	offset := (page - 1) * pageSize

	filters := service.ApprovalFilters{
		Status:          r.URL.Query().Get("status"),
		ActionType:      r.URL.Query().Get("action_type"),
		RequestedByUUID: r.URL.Query().Get("requested_by_uuid"),
		ProjectUUID:     r.URL.Query().Get("project_uuid"),
		FailureReason:   r.URL.Query().Get("failure_reason"),
		DateFrom:        r.URL.Query().Get("date_from"),
		DateTo:          r.URL.Query().Get("date_to"),
	}
	includeAll := scope.IsSuperAdmin || security.HasCapability(scope.AdminRole, "decide_approvals")

	approvals, _ := h.App.Approval.SearchVisibleToUser(userID, includeAll, filters, pageSize, offset, scope.ProjectIDs)
	totalCount, _ := h.App.Approval.CountVisibleToUser(userID, includeAll, filters, scope.ProjectIDs)
	summary, _ := h.App.Approval.SummariseVisibleToUser(userID, includeAll, scope.ProjectIDs)
	sla, _ := h.App.Approval.SummariseSlaVisibleToUser(userID, includeAll, scope.ProjectIDs, config.Get().AdminApprovalPendingWarnDays)

	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	data := h.adminBaseData(w, r, "Approvals")
	data["Approvals"] = approvals
	data["Summary"] = summary
	data["SLA"] = sla
	data["Filters"] = filters
	data["TotalCount"] = totalCount
	data["Page"] = page
	data["TotalPages"] = totalPages
	data["CanDecide"] = security.HasCapability(scope.AdminRole, "decide_approvals")
	data["CurrentUserID"] = userID
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "approvals.html", data)
}

// ApprovalApprove marks a pending request approved. The decision note is
// saved and the approval-policy receives a "decision.approved" audit entry.
func (h *AdminHandler) ApprovalApprove(w http.ResponseWriter, r *http.Request) {
	h.handleApprovalDecision(w, r, "approved")
}

// ApprovalReject marks a pending request rejected. Logs include the supplied
// failure_reason / note so the requester can see why it was denied.
func (h *AdminHandler) ApprovalReject(w http.ResponseWriter, r *http.Request) {
	h.handleApprovalDecision(w, r, "rejected")
}

func (h *AdminHandler) handleApprovalDecision(w http.ResponseWriter, r *http.Request, status string) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "decide_approvals") {
		return
	}
	audit := getAudit(r)
	approvalID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/approvals?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.approval." + status})
		sess.Save()
		redirect(w, r, "/admin/approvals?error=csrf")
		return
	}

	note := strings.TrimSpace(r.FormValue("note"))
	failureReason := strings.TrimSpace(r.FormValue("failure_reason"))

	updated, err := h.App.Approval.Decide(approvalID, status, actorID, note)
	if err != nil || !updated {
		redirect(w, r, "/admin/approvals?error=decision_failed")
		return
	}

	approval, _ := h.App.Approval.GetByID(approvalID)
	meta := service.AuditMeta{
		"actor_user_id": actorID,
		"approval_id":   approvalID,
		"target_type":   "approval_request",
		"target_id":     approvalID,
		"status":        status,
	}
	if approval != nil {
		meta["action_type"] = approval.ActionType
		if approval.ProjectID.Valid {
			meta["project_id"] = approval.ProjectID.Int64
		}
		if approval.ProjectUUID.Valid {
			meta["project_uuid"] = approval.ProjectUUID.String
		}
	}
	if status == "approved" {
		audit.LogSuccess("admin.approval.decision.approved", meta)
	} else {
		if failureReason != "" {
			meta["failure_reason"] = failureReason
		}
		audit.LogSuccess("admin.approval.decision.denied", meta)
	}
	sess.Save()
	redirect(w, r, "/admin/approvals?success="+status)
}

// ApprovalCancel lets the requester withdraw their own pending request.
func (h *AdminHandler) ApprovalCancel(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "view_approvals") {
		return
	}
	audit := getAudit(r)
	approvalID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/approvals?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.approval.cancel"})
		sess.Save()
		redirect(w, r, "/admin/approvals?error=csrf")
		return
	}

	note := strings.TrimSpace(r.FormValue("note"))
	updated, err := h.App.Approval.CancelByRequester(approvalID, actorID, note)
	if err != nil || !updated {
		redirect(w, r, "/admin/approvals?error=cancel_failed")
		return
	}
	audit.LogSuccess("admin.approval.cancelled", service.AuditMeta{
		"actor_user_id": actorID,
		"approval_id":   approvalID,
		"target_type":   "approval_request",
		"target_id":     approvalID,
	})
	sess.Save()
	redirect(w, r, "/admin/approvals?success=cancelled")
}

// ─── Cryptbin Admin ───────────────────────────────────────────────────────────

// CryptbinList shows all stored cryptbin items with size + expiry summary.
// Cryptbin admin is super-admin-only because items live outside the
// project/org scoping graph.
func (h *AdminHandler) CryptbinList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_cryptbin") {
		return
	}
	scope := h.scopeFor(r)

	storage := service.NewCryptbinStorage()
	ids, _ := storage.ListAll()
	var items []map[string]interface{}
	var totalSize int64
	for _, id := range ids {
		meta, err := storage.ReadMeta(id)
		if err != nil {
			continue
		}
		expired := storage.IsExpired(meta)
		totalSize += meta.SizeBytes
		items = append(items, map[string]interface{}{
			"ID":               id,
			"ItemType":         meta.ItemType,
			"OriginalFilename": meta.OriginalFilename,
			"MimeType":         meta.MimeType,
			"CipherAlg":        meta.CipherAlg,
			"WrappedDEKAlg":    meta.WrappedDEKAlg,
			"KEKVersion":       meta.KEKVersion,
			"SizeBytes":        meta.SizeBytes,
			"CreatedAt":        meta.CreatedAt,
			"ExpiresAt":        meta.ExpiresAt,
			"Expired":          expired,
			"WebAuthnBound":    meta.WebAuthnCredentialPublicID != "",
		})
	}

	data := h.adminBaseData(w, r, "Cryptbin")
	data["Items"] = items
	data["TotalCount"] = len(items)
	data["TotalSize"] = totalSize
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_cryptbin")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "cryptbin/list.html", data)
}

// CryptbinDelete removes a stored cryptbin item from filesystem storage.
func (h *AdminHandler) CryptbinDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_cryptbin") {
		return
	}
	audit := getAudit(r)
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/cryptbin?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.cryptbin.delete"})
		sess.Save()
		redirect(w, r, "/admin/cryptbin?error=csrf")
		return
	}

	storage := service.NewCryptbinStorage()
	if !storage.ValidateID(id) {
		redirect(w, r, "/admin/cryptbin?error=invalid")
		return
	}
	if err := storage.DeleteItem(id); err != nil {
		audit.LogFail("admin.cryptbin.delete.fail", service.AuditMeta{
			"actor_user_id":  actorID,
			"target_type":    "cryptbin",
			"target_id":      int64(0),
			"failure_reason": err.Error(),
		})
		sess.Save()
		redirect(w, r, "/admin/cryptbin?error=delete_failed")
		return
	}
	audit.LogSuccess("admin.cryptbin.delete.success", service.AuditMeta{
		"actor_user_id": actorID,
		"target_type":   "cryptbin",
	})
	sess.Save()
	redirect(w, r, "/admin/cryptbin?success=deleted")
}

// ─── Maintenance ──────────────────────────────────────────────────────────────

// Maintenance shows the most recent maintenance job runs and (for users with
// view_maintenance) lets the actor trigger a manual run via POST.
func (h *AdminHandler) Maintenance(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_maintenance") {
		return
	}
	scope := h.scopeFor(r)

	if r.Method == http.MethodPost {
		// Only super-admins can trigger a manual run.
		if !scope.IsSuperAdmin {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		r.ParseForm()
		sess, _ := security.GetSession(w, r)
		if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
			sess.Save()
			redirect(w, r, "/admin/maintenance?error=csrf")
			return
		}
		go h.App.Maintenance.RunAll("admin")
		if audit := getAudit(r); audit != nil {
			audit.LogSuccess("admin.maintenance.run", service.AuditMeta{
				"actor_user_id": scope.UserID,
				"trigger":       "admin",
			})
		}
		sess.Save()
		redirect(w, r, "/admin/maintenance?success=ran")
		return
	}

	rows, _ := h.DB.Query(`SELECT job_name, started_at, finished_at, status,
	                              COALESCE(rows_affected, 0), COALESCE(error_message, '')
	                      FROM maintenance_job_runs
	                      ORDER BY started_at DESC LIMIT 100`)
	var jobs []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var jobName, status, errMsg string
			var startedAt, finishedAt sql.NullTime
			var rowsAffected int64
			rows.Scan(&jobName, &startedAt, &finishedAt, &status, &rowsAffected, &errMsg)
			var duration string
			if startedAt.Valid && finishedAt.Valid {
				duration = finishedAt.Time.Sub(startedAt.Time).Truncate(time.Millisecond).String()
			}
			jobs = append(jobs, map[string]interface{}{
				"JobName":      jobName,
				"StartedAt":    startedAt.Time,
				"FinishedAt":   finishedAt.Time,
				"Status":       status,
				"RowsAffected": rowsAffected,
				"ErrorMessage": errMsg,
				"Duration":     duration,
			})
		}
	}

	data := h.adminBaseData(w, r, "Maintenance")
	data["Jobs"] = jobs
	data["CanRun"] = scope.IsSuperAdmin
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "maintenance.html", data)
}

// ─── Error Trace ──────────────────────────────────────────────────────────────

// ErrorTraceForm renders the decoder UI. The decoder accepts a short opaque
// trace code that an end-user might see on an error page and turns it back
// into the original event identifier the operator can search the audit log for.
func (h *AdminHandler) ErrorTraceForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "decode_error_trace") {
		return
	}
	data := h.adminBaseData(w, r, "Error Trace Decoder")
	data["Success"] = r.URL.Query().Get("success")
	templates.AdminPage(w, "error_trace.html", data)
}

// ErrorTraceDecode decodes a submitted trace code and renders the decoded value.
func (h *AdminHandler) ErrorTraceDecode(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "decode_error_trace") {
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/error-trace?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/error-trace?error=csrf")
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	decoded, err := security.DecodeErrorTrace(code)
	sess.Save()

	data := h.adminBaseData(w, r, "Error Trace Decoder")
	data["Code"] = code
	if err != nil {
		data["DecodeError"] = err.Error()
	} else {
		data["Decoded"] = decoded
	}
	templates.AdminPage(w, "error_trace.html", data)
}

// ─── Scope Debug ──────────────────────────────────────────────────────────────

// ScopeDebug shows the current actor's effective admin scope: role, capabilities,
// visible orgs/projects, plus the OAuth scope catalog (registered scopes and
// per-client allow-lists). Useful for diagnosing access issues.
func (h *AdminHandler) ScopeDebug(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_scope_debug") {
		return
	}
	scope := h.scopeFor(r)
	caps := security.CapabilitiesFor(scope.AdminRole)

	// Catalog of all OAuth scopes registered system-wide.
	var registeredScopes []map[string]interface{}
	if rows, _ := h.DB.Query(`SELECT name, COALESCE(description, ''), is_default FROM oauth_scopes ORDER BY name`); rows != nil {
		for rows.Next() {
			var name, desc string
			var isDefault bool
			rows.Scan(&name, &desc, &isDefault)
			registeredScopes = append(registeredScopes, map[string]interface{}{
				"Name": name, "Description": desc, "IsDefault": isDefault,
			})
		}
		rows.Close()
	}

	// Per-client scope allow-list, scoped to the actor.
	var clientScopes []map[string]interface{}
	var rows *sql.Rows
	if scope.IsSuperAdmin {
		rows, _ = h.DB.Query(`SELECT c.client_id, c.name, p.uuid, p.name, c.scopes
		                      FROM oauth_clients c JOIN projects p ON p.id = c.project_id
		                      ORDER BY p.name, c.name`)
	} else if len(scope.ProjectIDs) > 0 {
		ph, args := inClausePlaceholders(scope.ProjectIDs)
		rows, _ = h.DB.Query(`SELECT c.client_id, c.name, p.uuid, p.name, c.scopes
		                      FROM oauth_clients c JOIN projects p ON p.id = c.project_id
		                      WHERE p.id IN (`+ph+`)
		                      ORDER BY p.name, c.name`, args...)
	}
	if rows != nil {
		for rows.Next() {
			var pubID, clientName, projUUID, projName, scopesJSON string
			rows.Scan(&pubID, &clientName, &projUUID, &projName, &scopesJSON)
			var scopeList []string
			json.Unmarshal([]byte(scopesJSON), &scopeList)
			clientScopes = append(clientScopes, map[string]interface{}{
				"ClientPublicID": pubID, "ClientName": clientName,
				"ProjectUUID": projUUID, "ProjectName": projName,
				"Scopes": scopeList,
			})
		}
		rows.Close()
	}

	data := h.adminBaseData(w, r, "Scope Debug")
	data["Scope"] = map[string]interface{}{
		"UserID":            scope.UserID,
		"AdminRole":         scope.AdminRole,
		"IsAdmin":           scope.IsAdmin,
		"IsSuperAdmin":      scope.IsSuperAdmin,
		"OrganizationIDs":   scope.OrganizationIDs,
		"OrganizationUUIDs": scope.OrganizationUUIDs,
		"ProjectIDs":        scope.ProjectIDs,
		"ProjectUUIDs":      scope.ProjectUUIDs,
	}
	data["EffectiveCapabilities"] = caps
	data["RegisteredScopes"] = registeredScopes
	data["ClientScopes"] = clientScopes
	templates.AdminPage(w, "scope_debug.html", data)
}

// ─── Docs ─────────────────────────────────────────────────────────────────────

// docsGuidePages defines the ordered list of in-app documentation pages.
// Each entry maps a slug to a title, summary, and the page-template filename
// (relative to web/templates/admin/) that renders the page body.
var docsGuidePages = []struct {
	Slug, Title, Summary, PageFile string
}{
	{"overview", "Overview", "Platform purpose, capability model, and documentation map.", "docs/overview.html"},
	{"quick-start", "Administrator Quick Start", "First-session steps and immediate safety checks.", "docs/quick_start.html"},
	{"access-model", "Access Model and Scope", "How admin scope, super admin rules, and visibility boundaries work.", "docs/access_model.html"},
	{"users-and-enrolment", "Users and Enrolment", "User lifecycle, enrolment links, WebAuthn credentials, and status control.", "docs/users_and_enrolment.html"},
	{"projects-and-privileges", "Projects, Privileges, and Assignments", "Project governance, privilege levels, and assignment administration.", "docs/projects_and_privileges.html"},
	{"oauth-clients", "OAuth Clients and Authorisation Flows", "Client configuration, security posture, and flow expectations.", "docs/oauth_clients.html"},
	{"custom-claims", "Custom OIDC Claims", "Per-user and per-project key/value pairs merged into ID tokens and userinfo.", "docs/custom_claims.html"},
	{"approvals", "Approvals Workflow", "Submission, decisioning, denial reasons, and operational handling.", "docs/approvals.html"},
	{"audit-and-security", "Audit and Security Operations", "Audit search/export, security indicators, and response actions.", "docs/audit_and_security.html"},
	{"metrics-and-vmagent", "Metrics and vmagent Event Push", "Dashboard metrics, event push configuration, and validation.", "docs/metrics_and_vmagent.html"},
	{"maintenance-and-dr", "Maintenance, Backup, and Recovery", "Routine maintenance, backup standards, and recovery rehearsal.", "docs/maintenance_and_dr.html"},
	{"troubleshooting", "Troubleshooting and Diagnostics", "Common faults, diagnostic sequence, and corrective actions.", "docs/troubleshooting.html"},
	{"reference", "Reference and Glossary", "Environment variable reference, route index, and glossary.", "docs/reference.html"},
}

// DocsHome renders the requested guide page (defaulting to "overview"). The
// {page} URL parameter chooses between the slugs in docsGuidePages.
func (h *AdminHandler) DocsHome(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminAuth(w, r); !ok {
		return
	}
	if !h.requireCapability(w, r, "view_docs") {
		return
	}

	slug := chi.URLParam(r, "page")
	if slug == "" {
		slug = "overview"
	}

	idx := -1
	for i, p := range docsGuidePages {
		if p.Slug == slug {
			idx = i
			break
		}
	}
	if idx == -1 {
		http.NotFound(w, r)
		return
	}
	current := docsGuidePages[idx]

	var prevSlug, prevTitle, nextSlug, nextTitle string
	if idx > 0 {
		prevSlug = docsGuidePages[idx-1].Slug
		prevTitle = docsGuidePages[idx-1].Title
	}
	if idx < len(docsGuidePages)-1 {
		nextSlug = docsGuidePages[idx+1].Slug
		nextTitle = docsGuidePages[idx+1].Title
	}

	pages := make([]map[string]interface{}, len(docsGuidePages))
	for i, p := range docsGuidePages {
		pages[i] = map[string]interface{}{
			"Slug": p.Slug, "Title": p.Title, "Summary": p.Summary,
		}
	}

	data := h.adminBaseData(w, r, "Documentation: "+current.Title)
	data["DocsPages"] = pages
	data["CurrentSlug"] = slug
	data["CurrentTitle"] = current.Title
	data["CurrentSummary"] = current.Summary
	data["PrevSlug"] = prevSlug
	data["PrevTitle"] = prevTitle
	data["NextSlug"] = nextSlug
	data["NextTitle"] = nextTitle
	// Each docs page defines a "doc_body" template; AdminDocsPage stitches it
	// together with the shared docs.html sidebar/navigation chrome.
	templates.AdminDocsPage(w, current.PageFile, data)
}

// ─── Switch Identity ──────────────────────────────────────────────────────────

// SwitchRestore reverts an active "act-as" / impersonation back to the
// original admin's user_id stored in impersonator_user_id. Doesn't require
// requireAdminAuth because the constraint set is intentionally narrow:
//   - impersonator_user_id MUST be present (only set during an active switch
//     by a super-admin via OrganizationSwitchAdmin)
//   - the actor returns to the user_id they had before the switch
//
// so the only state change possible is restoring an existing trusted ID.
func (h *AdminHandler) SwitchRestore(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/dashboard?error=bad_request")
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/dashboard?error=csrf")
		return
	}

	origID := sess.GetInt("impersonator_user_id")
	if origID == 0 {
		redirect(w, r, "/admin/dashboard")
		return
	}
	// Verify the original ID is still an active admin before restoring; if
	// the original admin lost their role mid-switch we don't want to grant
	// access back.
	scope := h.App.Scope.Build(origID)
	if !scope.IsAdmin {
		sess.Delete("impersonator_user_id")
		sess.Delete("user_id")
		sess.Save()
		redirect(w, r, "/admin/login")
		return
	}

	sess.Set("user_id", origID)
	sess.Delete("impersonator_user_id")
	sess.RegenerateID()
	sess.Save()
	if audit := getAudit(r); audit != nil {
		audit.LogSuccess("admin.switch.restore", service.AuditMeta{
			"actor_user_id": origID,
		})
	}
	redirect(w, r, "/admin/dashboard")
}

// ─── Organization import/export helpers ──────────────────────────────────────

// OrganizationSwitchAdmin starts an "act-as" switch into another user's
// session. Gated by switch_organization_admin (super-admin only). The target
// user must belong to the organisation being switched into, and the actor's
// original ID is preserved in impersonator_user_id so SwitchRestore can revert.
func (h *AdminHandler) OrganizationSwitchAdmin(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "switch_organization_admin") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
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
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.org.switch_admin"})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}

	userUUID := r.FormValue("user_uuid")
	var targetUserID, orgID, targetUserOrgID int
	h.DB.QueryRow("SELECT id, organization_id FROM users WHERE uuid=? AND status='active'", userUUID).Scan(&targetUserID, &targetUserOrgID)
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)

	if targetUserID == 0 || orgID == 0 || targetUserOrgID != orgID {
		// Target user must actually belong to the organisation we're switching
		// admin for — otherwise this is an attempt to elevate via a stranger.
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=invalid")
		return
	}

	// Refuse to chain switches on top of an existing impersonation —
	// otherwise the audit trail of "who is acting as whom" gets ambiguous.
	if sess.GetInt("impersonator_user_id") != 0 {
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=already_switched")
		return
	}

	sess.Set("impersonator_user_id", actorID)
	sess.Set("user_id", targetUserID)
	sess.RegenerateID()
	sess.Save()
	audit.LogSuccess("admin.org.switch_admin", service.AuditMeta{
		"actor_user_id":     actorID,
		"target_user_id":    targetUserID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
	})
	redirect(w, r, "/admin/dashboard")
}

// OrganizationImportUsers bulk-creates users in an org from a newline-separated
// list of display labels. Capped to prevent runaway requests; each row is
// length-validated.
func (h *AdminHandler) OrganizationImportUsers(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
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
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.org.import_users"})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}

	var orgID int
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)
	if orgID == 0 {
		http.NotFound(w, r)
		return
	}

	labels := splitLines(r.FormValue("labels"))
	const maxImport = 500
	if len(labels) > maxImport {
		labels = labels[:maxImport]
	}
	var imported int
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" || len(label) > 120 {
			continue
		}
		userUUID := uuid.NewString()
		_, err := h.DB.Exec("INSERT INTO users (organization_id, uuid, display_label, status) VALUES (?,?,?,'active')", orgID, userUUID, label)
		if err == nil {
			imported++
		}
	}

	audit.LogSuccess("admin.org.import_users", service.AuditMeta{
		"actor_user_id":     actorID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
		"imported_count":    imported,
	})
	sess.Save()
	redirect(w, r, "/admin/organisations/"+orgUUID+"?success=imported&count="+strconv.Itoa(imported))
}

// OrganizationExportEnrollmentURLs streams a CSV of one fresh enrolment URL
// per active user in the org. Token bytes are hashed before persistence — the
// raw token only appears in the streamed CSV body and the user's URL.
func (h *AdminHandler) OrganizationExportEnrollmentURLs(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_organizations") {
		return
	}
	scope := h.scopeFor(r)
	audit := getAudit(r)
	orgUUID := chi.URLParam(r, "organizationUuid")
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
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "admin.org.export_enrollment"})
		sess.Save()
		redirect(w, r, "/admin/organisations/"+orgUUID+"?error=csrf")
		return
	}

	var orgID int
	h.DB.QueryRow("SELECT id FROM organizations WHERE uuid=?", orgUUID).Scan(&orgID)
	if orgID == 0 {
		http.NotFound(w, r)
		return
	}

	rows, _ := h.DB.Query("SELECT id, display_label FROM users WHERE organization_id=? AND status='active'", orgID)
	cfg := config.Get()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=enrollment_urls.csv")
	fmt.Fprintln(w, "display_label,enrollment_url")

	exported := 0
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var userID int
			var label string
			rows.Scan(&userID, &label)
			token := hexToken(32)
			tokenHash := security.HashToken(token)
			expiry := time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
			h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_token_"+tokenHash, fmt.Sprintf("%d", userID))
			h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)", "enrollment_expiry_"+tokenHash, expiry)
			url := cfg.AppURL + "/enroll?token=" + token
			fmt.Fprintf(w, "%s,%s\n", csvField(label), csvField(url))
			exported++
		}
	}

	audit.LogSuccess("admin.org.export_enrollment_urls", service.AuditMeta{
		"actor_user_id":     actorID,
		"organization_id":   orgID,
		"organization_uuid": orgUUID,
		"exported_count":    exported,
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func hexToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hashSecret(secret string) string {
	h := security.HashSecret(secret)
	return h
}

func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func b64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
