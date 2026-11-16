// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

type PortalHandler struct {
	App      *App
	WebAuthn *service.WebAuthnService
}

func (h *PortalHandler) LoginForm(w http.ResponseWriter, r *http.Request) {
	sess, err := security.GetSession(w, r)
	if err != nil {
		http.Error(w, "Session error", 500)
		return
	}
	csrf := security.GenerateCSRF(sess)
	sess.Save()
	templates.Standalone(w, "portal/login.html", map[string]interface{}{
		"CSRFToken": csrf,
	})
}

func (h *PortalHandler) LoginChallenge(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	if err := r.ParseForm(); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	audit := getAudit(r)
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "webauthn.login.portal.challenge", 60, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "webauthn.login.portal.challenge"})
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)

	sess.Set("portal_webauthn_challenge", map[string]interface{}{
		"value":      challengeB64,
		"expires_at": time.Now().Add(120 * time.Second).Unix(),
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

func (h *PortalHandler) LoginVerify(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	csrf := jsonStrField(body, "csrf_token")
	if !security.ValidateCSRF(sess, csrf) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "portal.login_verify"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "webauthn.login.portal.verify", 20, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"action": "webauthn.login.portal.verify"})
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	credentialID := jsonStrField(body, "id")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")
	authenticatorData := jsonNestedStr(body, "response", "authenticatorData")
	signature := jsonNestedStr(body, "response", "signature")

	if credentialID == "" || clientDataJSON == "" || authenticatorData == "" || signature == "" {
		audit.LogFail("portal.login.fail", service.AuditMeta{"failure_reason": "Missing credential data"})
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	cred, err := h.WebAuthn.GetCredentialByPublicID(credentialID)
	if err != nil || cred == nil {
		audit.LogFail("portal.login.fail", service.AuditMeta{"failure_reason": "Credential not found", "webauthn_credential_public_id": credentialID})
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	challengeState := sess.Get("portal_webauthn_challenge")
	expectedChallenge, expiresAt := extractChallenge(challengeState)
	if expectedChallenge == "" || (expiresAt > 0 && time.Now().Unix() > expiresAt) {
		sess.Delete("portal_webauthn_challenge")
		audit.LogFail("portal.login.fail", service.AuditMeta{"failure_reason": "Challenge missing or expired", "actor_user_id": cred.UserID})
		sess.Save()
		jsonError(w, "session_expired", http.StatusBadRequest)
		return
	}
	sess.Delete("portal_webauthn_challenge")

	if ok, reason := h.WebAuthn.VerifyAssertionDetailed(credentialID, clientDataJSON, authenticatorData, signature, expectedChallenge); !ok {
		audit.LogFail("portal.login.fail", service.AuditMeta{"failure_reason": reason, "actor_user_id": cred.UserID})
		sess.Save()
		jsonError(w, "invalid_credential", http.StatusBadRequest)
		return
	}

	var userStatus string
	h.WebAuthn.DB().QueryRow("SELECT status FROM users WHERE id=? LIMIT 1", cred.UserID).Scan(&userStatus)
	if userStatus != "active" {
		audit.LogFail("portal.login.fail", service.AuditMeta{"failure_reason": "User account inactive", "actor_user_id": cred.UserID})
		sess.Save()
		jsonError(w, "invalid_credential", http.StatusForbidden)
		return
	}

	sess.Set("user_id", cred.UserID)
	sess.Set("auth_time", time.Now().Unix())
	sess.Set("login_credential_id", cred.ID)
	sess.RegenerateID()

	audit.LogSuccess("portal.login.success", service.AuditMeta{"actor_user_id": cred.UserID, "webauthn_credential_id": cred.ID, "webauthn_credential_public_id": credentialID})

	returnTo := sess.GetString("oauth_return_to")
	if returnTo == "" {
		returnTo = "/portal"
	}
	sess.Delete("oauth_return_to")
	sess.Save()

	jsonOK(w, map[string]interface{}{"success": true, "redirect": returnTo})
}

func (h *PortalHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	if !h.checkPortalAuth(userID) {
		sess.Save()
		redirect(w, r, "/portal/login")
		return
	}

	db := h.WebAuthn.DB()
	var user map[string]interface{}
	row := db.QueryRow("SELECT id, uuid, display_label, status, created_at FROM users WHERE id=?", userID)
	var id int
	var uuid, label, status string
	var createdAt time.Time
	if err := row.Scan(&id, &uuid, &label, &status, &createdAt); err != nil {
		http.Error(w, "User not found", 500)
		return
	}
	user = map[string]interface{}{"id": id, "uuid": uuid, "display_label": label, "status": status, "created_at": createdAt}

	rows, _ := db.Query(
		`SELECT p.uuid, p.name, upr.privilege_level, ppl.name AS privilege_name
		 FROM projects p
		 JOIN user_project_roles upr ON p.id=upr.project_id
		 LEFT JOIN project_privilege_levels ppl ON ppl.project_id=upr.project_id AND ppl.level=upr.privilege_level
		 WHERE upr.user_id=? AND p.status='active' ORDER BY p.name`, userID)
	var projects []map[string]interface{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var puuid, pname string
			var plevel int
			var privName *string
			rows.Scan(&puuid, &pname, &plevel, &privName)
			label := resolvePrivilegeLabel(plevel, privName)
			projects = append(projects, map[string]interface{}{"uuid": puuid, "name": pname, "privilege_level": plevel, "privilege_label": label})
		}
	}

	credRows, _ := db.Query("SELECT id, credential_id, label, created_at, last_used_at FROM webauthn_credentials WHERE user_id=? ORDER BY created_at DESC", userID)
	var creds []map[string]interface{}
	if credRows != nil {
		defer credRows.Close()
		for credRows.Next() {
			var cid int
			var credPubID string
			var clabel *string
			var createdAt time.Time
			var lastUsedAt *time.Time
			credRows.Scan(&cid, &credPubID, &clabel, &createdAt, &lastUsedAt)
			label := ""
			if clabel != nil {
				label = *clabel
			}
			creds = append(creds, map[string]interface{}{"id": cid, "credential_id": credPubID, "label": label, "created_at": createdAt, "last_used_at": lastUsedAt})
		}
	}

	csrf := security.GenerateCSRF(sess)
	sess.Save()

	templates.Standalone(w, "portal/dashboard.html", map[string]interface{}{
		"Title":             "Portal",
		"User":              user,
		"Projects":          projects,
		"Credentials":       creds,
		"LoginCredentialID": sess.GetInt("login_credential_id"),
		"CSRFToken":         csrf,
	})
}

func (h *PortalHandler) AddKeyInit(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	if !h.checkPortalAuth(userID) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	db := h.WebAuthn.DB()
	var userUUID, userLabel string
	db.QueryRow("SELECT uuid, display_label FROM users WHERE id=?", userID).Scan(&userUUID, &userLabel)
	if userLabel == "" {
		userLabel = "User"
	}

	options := h.WebAuthn.GenerateRegistrationOptions(userUUID, userLabel)
	challenge, _ := options["challenge"].(string)
	sess.Set("portal_registration_challenge", challenge)
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	options["csrf_token"] = nextCSRF
	jsonOK(w, options)
}

func (h *PortalHandler) AddKeyComplete(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	if !h.checkPortalAuth(userID) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	csrf := jsonStrField(body, "csrf_token")
	if !security.ValidateCSRF(sess, csrf) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "portal.add_key_complete"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	attestationObject := jsonNestedStr(body, "response", "attestationObject")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")
	label := jsonStrField(body, "label")
	if label == "" {
		label = "Unnamed Key"
	}

	if attestationObject == "" || clientDataJSON == "" {
		jsonError(w, "invalid_credential_data", http.StatusBadRequest)
		return
	}

	expectedChallenge := sess.GetString("portal_registration_challenge")
	sess.Delete("portal_registration_challenge")

	if expectedChallenge == "" || !h.WebAuthn.VerifyRegistrationResponse(clientDataJSON, expectedChallenge) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Registration challenge or origin validation failed", "actor_user_id": userID})
		sess.Save()
		jsonError(w, "invalid_registration_response", http.StatusBadRequest)
		return
	}

	credentialID, publicKey, signCounter, err := h.WebAuthn.ExtractPublicKeyFromAttestation(attestationObject)
	if err != nil {
		jsonError(w, "failed_to_extract_public_key", http.StatusBadRequest)
		return
	}

	credDBID, err := h.WebAuthn.StoreCredential(userID, credentialID, publicKey, signCounter, label)
	if err != nil {
		jsonError(w, "internal_error", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("portal.key.add", service.AuditMeta{"actor_user_id": userID, "webauthn_credential_id": credDBID})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]interface{}{"success": true, "csrf_token": nextCSRF})
}

func (h *PortalHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	userID := sess.GetInt("user_id")
	if !h.checkPortalAuth(userID) {
		redirect(w, r, "/portal/login")
		return
	}

	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/portal?error=bad_request")
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/portal?error=csrf")
		return
	}

	audit := getAudit(r)
	credentialPublicID := chi.URLParam(r, "credentialPublicId")
	loginCredID := sess.GetInt("login_credential_id")

	db := h.WebAuthn.DB()
	var credID, credUserID int
	err := db.QueryRow("SELECT id, user_id FROM webauthn_credentials WHERE credential_id=?", credentialPublicID).Scan(&credID, &credUserID)
	if err != nil || credUserID != userID {
		sess.Save()
		redirect(w, r, "/portal?error=unauthorized")
		return
	}

	var keyCount int
	db.QueryRow("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?", userID).Scan(&keyCount)
	if keyCount <= 1 {
		sess.Save()
		redirect(w, r, "/portal?error=min_keys")
		return
	}

	if credID == loginCredID {
		sess.Save()
		redirect(w, r, "/portal?error=cannot_delete_current_key")
		return
	}

	db.Exec("DELETE FROM webauthn_credentials WHERE id=?", credID)
	audit.LogSuccess("portal.key.delete", service.AuditMeta{"actor_user_id": userID, "webauthn_credential_id": credID, "webauthn_credential_public_id": credentialPublicID})
	sess.Save()

	redirect(w, r, "/portal?success=key_deleted")
}

func (h *PortalHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/portal?error=bad_request")
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/portal?error=csrf")
		return
	}
	sess.Destroy()
	redirect(w, r, "/portal/login")
}

func (h *PortalHandler) checkPortalAuth(userID int) bool {
	if userID == 0 {
		return false
	}
	var status string
	h.WebAuthn.DB().QueryRow("SELECT status FROM users WHERE id=? LIMIT 1", userID).Scan(&status)
	return status == "active"
}

// extractChallenge pulls value/expires_at out of a session challenge state (map or string).
func extractChallenge(v interface{}) (string, int64) {
	switch t := v.(type) {
	case map[string]interface{}:
		val, _ := t["value"].(string)
		exp, _ := t["expires_at"].(int64)
		return val, exp
	case string:
		return t, 0
	}
	return "", 0
}

// resolvePrivilegeLabel maps numeric level to a label using the custom name if set.
func resolvePrivilegeLabel(level int, name *string) string {
	if name != nil && *name != "" {
		return *name
	}
	switch level {
	case 10:
		return "Owner"
	case 5:
		return "Admin"
	case 3:
		return "Member"
	case 1:
		return "Viewer"
	default:
		return "Level " + intStr(level)
	}
}

func intStr(n int) string {
	return fmt.Sprintf("%d", n)
}

// jsonStrField extracts a string from a flat JSON body map.
func jsonStrField(body map[string]json.RawMessage, key string) string {
	raw, ok := body[key]
	if !ok {
		return ""
	}
	var s string
	json.Unmarshal(raw, &s)
	return s
}

// jsonIntField extracts an int from a flat JSON body map, accepting either
// a JSON number or a numeric string.
func jsonIntField(body map[string]json.RawMessage, key string) int {
	raw, ok := body[key]
	if !ok {
		return 0
	}

	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseInt(s)
	}

	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int(f)
	}

	return 0
}

// jsonNestedStr extracts a string from body[outer][inner].
func jsonNestedStr(body map[string]json.RawMessage, outer, inner string) string {
	raw, ok := body[outer]
	if !ok {
		return ""
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return ""
	}
	var s string
	json.Unmarshal(nested[inner], &s)
	return s
}
