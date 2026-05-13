package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"

	"blackwall/internal/config"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

type BootstrapHandler struct {
	App      *App
	WebAuthn *service.WebAuthnService
	DB       *sql.DB
}

var enrollmentTokenRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (h *BootstrapHandler) isValidToken(t string) bool {
	return enrollmentTokenRe.MatchString(t)
}

// BootstrapForm shows the initial WebAuthn registration for the first admin.
func (h *BootstrapHandler) BootstrapForm(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "bootstrap.token.verify", 20, 900) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	var complete string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_complete'").Scan(&complete)
	if complete == "1" {
		http.Error(w, "Bootstrap already complete. Please login at /admin/login", http.StatusForbidden)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" || !h.isValidToken(token) {
		http.Error(w, "Invalid bootstrap token", http.StatusBadRequest)
		return
	}

	var storedToken string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_token'").Scan(&storedToken)
	// Constant-time compare so we don't leak token-validity timing.
	if storedToken == "" || !security.ConstantTimeEqual(storedToken, token) {
		http.Error(w, "Invalid or expired bootstrap token", http.StatusBadRequest)
		return
	}

	var expiry string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_expiry'").Scan(&expiry)
	if !isTokenValid(expiry) {
		http.Error(w, "Bootstrap token expired", http.StatusBadRequest)
		return
	}

	var userID int
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_user_id'").Scan(&userID)
	if userID == 0 {
		http.Error(w, "Bootstrap user not found", http.StatusBadRequest)
		return
	}

	var userUUID, userLabel, orgName string
	var orgLogo *string
	h.DB.QueryRow(`SELECT u.uuid, u.display_label, o.name, o.logo_url
		FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.id=?`, userID).
		Scan(&userUUID, &userLabel, &orgName, &orgLogo)
	if userLabel == "" {
		userLabel = "Admin"
	}

	options := h.WebAuthn.GenerateRegistrationOptions(userUUID, userLabel)
	challenge, _ := options["challenge"].(string)

	sess, _ := security.GetSession(w, r)
	sess.Set("bootstrap_registration_context", map[string]interface{}{
		"token":     token,
		"user_id":   userID,
		"challenge": challenge,
	})
	sess.Save()

	templates.Standalone(w, "bootstrap/enroll.html", map[string]interface{}{
		"Token":     token,
		"Options":   options,
		"User":      map[string]interface{}{"uuid": userUUID, "display_label": userLabel},
		"UserLabel": userLabel,
		"Organization": map[string]interface{}{"name": orgName, "logo_url": orgLogo},
	})
}

// EnrollWebAuthn completes bootstrap WebAuthn registration.
func (h *BootstrapHandler) EnrollWebAuthn(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "bootstrap.token.verify", 20, 900) {
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	token := jsonStrField(body, "token")
	if token == "" || !h.isValidToken(token) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid token format"})
		jsonError(w, "invalid_token", http.StatusBadRequest)
		return
	}

	var storedToken string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_token'").Scan(&storedToken)
	if storedToken == "" || !security.ConstantTimeEqual(storedToken, token) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid token"})
		jsonError(w, "invalid_token", http.StatusBadRequest)
		return
	}

	var expiry string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_expiry'").Scan(&expiry)
	if !isTokenValid(expiry) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Bootstrap token expired"})
		jsonError(w, "token_expired", http.StatusBadRequest)
		return
	}

	var userID int
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key='bootstrap_user_id'").Scan(&userID)
	if userID == 0 {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "User not found"})
		jsonError(w, "user_not_found", http.StatusBadRequest)
		return
	}

	sess, _ := security.GetSession(w, r)
	ctx := extractSessionMap(sess.Get("bootstrap_registration_context"))
	sess.Delete("bootstrap_registration_context")

	expectedChallenge, _ := ctx["challenge"].(string)
	contextToken, _ := ctx["token"].(string)
	contextUserID := toInt(ctx["user_id"])

	attestationObject := jsonNestedStr(body, "response", "attestationObject")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")

	if attestationObject == "" || clientDataJSON == "" {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid credential data"})
		sess.Save()
		jsonError(w, "invalid_credential_data", http.StatusBadRequest)
		return
	}

	if expectedChallenge == "" || contextToken == "" || contextToken != token || contextUserID != userID ||
		!h.WebAuthn.VerifyRegistrationResponse(clientDataJSON, expectedChallenge) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Registration challenge or origin validation failed"})
		sess.Save()
		jsonError(w, "invalid_registration_response", http.StatusBadRequest)
		return
	}

	credentialID, publicKey, signCounter, err := h.WebAuthn.ExtractPublicKeyFromAttestation(attestationObject)
	if err != nil {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Failed to extract public key"})
		sess.Save()
		jsonError(w, "invalid_attestation", http.StatusBadRequest)
		return
	}

	credDBID, err := h.WebAuthn.StoreCredential(userID, credentialID, publicKey, signCounter, "Bootstrap Key")
	if err != nil {
		sess.Save()
		jsonError(w, "internal_error", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("webauthn.registration.success", service.AuditMeta{"actor_user_id": userID, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credentialID})

	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES ('bootstrap_complete','1') ON DUPLICATE KEY UPDATE config_value='1'")
	h.DB.Exec("DELETE FROM system_config WHERE config_key IN ('bootstrap_token','bootstrap_expiry','bootstrap_user_id')")

	sess.Save()
	jsonOK(w, map[string]interface{}{"success": true, "redirect": "/admin/login"})
}

// EnrollForm shows the user enrollment page via token.
func (h *BootstrapHandler) EnrollForm(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "enrollment.token.verify", 20, 900) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" || !h.isValidToken(token) {
		http.Error(w, "Invalid enrollment link", http.StatusBadRequest)
		return
	}

	// Tokens are persisted as SHA-256 hashes; the URL carries the raw token
	// so the recipient can use it once. We hash before lookup.
	tokenHash := security.HashToken(token)
	var userIDStr string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key=?", "enrollment_token_"+tokenHash).Scan(&userIDStr)
	if userIDStr == "" {
		http.Error(w, "Invalid or expired enrollment token", http.StatusBadRequest)
		return
	}
	userID := parseInt(userIDStr)

	var expiry string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key=?", "enrollment_expiry_"+tokenHash).Scan(&expiry)
	if !isTokenValid(expiry) {
		http.Error(w, "Enrollment token expired", http.StatusBadRequest)
		return
	}

	var userUUID, userLabel, orgName string
	var orgLogo *string
	err := h.DB.QueryRow(`SELECT u.uuid, u.display_label, o.name, o.logo_url
		FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.id=?`, userID).
		Scan(&userUUID, &userLabel, &orgName, &orgLogo)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}
	if userLabel == "" {
		userLabel = "User"
	}

	options := h.WebAuthn.GenerateRegistrationOptions(userUUID, userLabel)
	challenge, _ := options["challenge"].(string)

	sess, _ := security.GetSession(w, r)
	sess.Set("enrollment_registration_context", map[string]interface{}{
		"token":     token,
		"user_id":   userID,
		"challenge": challenge,
	})
	sess.Save()

	templates.Standalone(w, "enroll.html", map[string]interface{}{
		"Token":     token,
		"Options":   options,
		"User":      map[string]interface{}{"uuid": userUUID, "display_label": userLabel},
		"UserLabel": userLabel,
		"Organization": map[string]interface{}{"name": orgName, "logo_url": orgLogo},
	})
}

// EnrollKey completes user enrollment.
func (h *BootstrapHandler) EnrollKey(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "enrollment.token.verify", 20, 900) {
		jsonError(w, "too_many_requests", http.StatusTooManyRequests)
		return
	}

	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	token := jsonStrField(body, "token")
	if token == "" || !h.isValidToken(token) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid token format"})
		jsonError(w, "invalid_token", http.StatusBadRequest)
		return
	}

	tokenHash := security.HashToken(token)
	var userIDStr string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key=?", "enrollment_token_"+tokenHash).Scan(&userIDStr)
	if userIDStr == "" {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid token"})
		jsonError(w, "invalid_token", http.StatusBadRequest)
		return
	}
	userID := parseInt(userIDStr)

	var expiry string
	h.DB.QueryRow("SELECT config_value FROM system_config WHERE config_key=?", "enrollment_expiry_"+tokenHash).Scan(&expiry)
	if !isTokenValid(expiry) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Enrollment token expired"})
		jsonError(w, "token_expired", http.StatusBadRequest)
		return
	}

	sess, _ := security.GetSession(w, r)
	ctx := extractSessionMap(sess.Get("enrollment_registration_context"))
	sess.Delete("enrollment_registration_context")

	expectedChallenge, _ := ctx["challenge"].(string)
	contextToken, _ := ctx["token"].(string)
	contextUserID := toInt(ctx["user_id"])

	attestationObject := jsonNestedStr(body, "response", "attestationObject")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")

	if attestationObject == "" || clientDataJSON == "" {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Invalid credential data"})
		sess.Save()
		jsonError(w, "invalid_credential_data", http.StatusBadRequest)
		return
	}

	if expectedChallenge == "" || contextToken == "" || contextToken != token || contextUserID != userID ||
		!h.WebAuthn.VerifyRegistrationResponse(clientDataJSON, expectedChallenge) {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Registration challenge or origin validation failed"})
		sess.Save()
		jsonError(w, "invalid_registration_response", http.StatusBadRequest)
		return
	}

	credentialID, publicKey, signCounter, err := h.WebAuthn.ExtractPublicKeyFromAttestation(attestationObject)
	if err != nil {
		audit.LogFail("webauthn.registration.fail", service.AuditMeta{"failure_reason": "Failed to extract public key"})
		sess.Save()
		jsonError(w, "invalid_attestation", http.StatusBadRequest)
		return
	}

	credDBID, err := h.WebAuthn.StoreCredential(userID, credentialID, publicKey, signCounter, "Enrolled Key")
	if err != nil {
		sess.Save()
		jsonError(w, "internal_error", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("webauthn.registration.success", service.AuditMeta{"actor_user_id": userID, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credentialID})

	h.DB.Exec("DELETE FROM system_config WHERE config_key IN (?,?)", "enrollment_token_"+tokenHash, "enrollment_expiry_"+tokenHash)

	sess.Save()
	jsonOK(w, map[string]interface{}{"success": true, "redirect": "/portal/login"})
}

// OrgSignupForm renders the organisation self-registration form.
func (h *BootstrapHandler) OrgSignupForm(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	csrf := security.GenerateCSRF(sess)
	sess.Save()
	templates.Standalone(w, "organizations/signup.html", map[string]interface{}{"CSRFToken": csrf})
}

// OrgSignup processes organisation self-registration.
func (h *BootstrapHandler) OrgSignup(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "organization.signup", 5, 3600) {
		redirect(w, r, "/organisations/signup?error=rate_limited")
		return
	}

	sess, _ := security.GetSession(w, r)
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/organisations/signup?error=csrf")
		return
	}
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/organisations/signup?error=csrf")
		return
	}

	name := r.FormValue("name")
	slug := r.FormValue("slug")
	adminLabel := r.FormValue("admin_display_label")
	if name == "" || slug == "" || adminLabel == "" {
		sess.Save()
		redirect(w, r, "/organisations/signup?error=invalid")
		return
	}
	slugRe := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)
	if !slugRe.MatchString(slug) {
		sess.Save()
		redirect(w, r, "/organisations/signup?error=slug")
		return
	}

	orgUUID := uuid.NewString()
	res, err := h.DB.Exec("INSERT INTO organizations (uuid, name, slug, status) VALUES (?,?,?,'active')", orgUUID, name, slug)
	if err != nil {
		sess.Save()
		redirect(w, r, "/organisations/signup?error=duplicate")
		return
	}
	orgID, _ := res.LastInsertId()

	userUUID := uuid.NewString()
	userRes, _ := h.DB.Exec("INSERT INTO users (organization_id, uuid, display_label, status) VALUES (?,?,?,'active')", orgID, userUUID, adminLabel)
	userID, _ := userRes.LastInsertId()

	h.DB.Exec("UPDATE organizations SET admin_user_id=? WHERE id=?", userID, orgID)

	token := generateHexToken(32)
	signupTokenHash := security.HashToken(token)
	expiry := time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
		"enrollment_token_"+signupTokenHash, fmt.Sprintf("%d", userID))
	h.DB.Exec("INSERT INTO system_config (config_key, config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
		"enrollment_expiry_"+signupTokenHash, expiry)

	cfg := config.Get()
	enrollmentLink := cfg.AppURL + "/enroll?token=" + token
	csrf := security.GenerateCSRF(sess)
	sess.Save()

	templates.Standalone(w, "organizations/signup.html", map[string]interface{}{
		"CSRFToken":        csrf,
		"Success":          true,
		"EnrollmentLink":   enrollmentLink,
		"OrganizationName": name,
	})
}

// isTokenValid checks that a datetime string from system_config is in the future.
func isTokenValid(expiry string) bool {
	if expiry == "" {
		return false
	}
	t, err := time.Parse("2006-01-02 15:04:05", expiry)
	if err != nil {
		return false
	}
	return time.Now().Before(t)
}

func extractSessionMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	return 0
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func generateHexToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
