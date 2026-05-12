package handler

import (
	"encoding/json"
	"net/http"

	"blackwall/internal/middleware"
	"blackwall/internal/security"
	"blackwall/internal/service"
)

type App struct {
	WebAuthn    *service.WebAuthnService
	OAuth       *service.OAuthService
	JWT         *service.JWTManager
	Audit       *service.AuditLogger
	AdminAuth   *service.AdminAuthService
	Approval    *service.ApprovalService
	Scope       *service.AdminScopeBuilder
	Claims      *service.OIDCClaimsService
	Maintenance *service.MaintenanceService
	RateLimit   *security.RateLimiter
}

func jsonError(w http.ResponseWriter, err string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": err})
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func getAudit(r *http.Request) *service.AuditLogger {
	return middleware.GetAuditLogger(r)
}

func getIP(r *http.Request) string {
	return middleware.GetIP(r)
}

func redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusFound)
}

func parseJSON(r *http.Request, dst interface{}) bool {
	return json.NewDecoder(r.Body).Decode(dst) == nil
}
