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
	Features    *service.FeatureFlagService
	Webhooks    *service.WebhookService
	Sessions    *service.SessionStore
	Branding    *service.BrandingService
	AuditChain  *service.AuditChainService
	AdminTokens *service.AdminTokenService
	SCIM        *service.SCIMService
	SAML        *service.SAMLService
}

func jsonError(w http.ResponseWriter, err string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   err,
		"message": humanizeError(err),
	})
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

const (
	flashAdminTokenPlaintext = "flash_admin_token_plaintext"
	flashAdminTokenName      = "flash_admin_token_name"
	flashClientSecretPrefix  = "flash_client_secret:"
	flashEnrollmentPrefix    = "flash_enrollment_token:"
)

func popSessionString(sess *security.Session, key string) string {
	value := sess.GetString(key)
	sess.Delete(key)
	return value
}

func parseJSON(r *http.Request, dst interface{}) bool {
	return json.NewDecoder(r.Body).Decode(dst) == nil
}

func humanizeError(err string) string {
	switch err {
	case "bad_request":
		return "The request was invalid."
	case "invalid_csrf":
		return "Your session token was invalid or expired. Please reload the page and try again."
	case "too_many_requests", "rate_limit_exceeded":
		return "Too many requests. Please wait a moment and try again."
	case "invalid_credential":
		return "The security key response could not be verified."
	case "invalid_credential_binding":
		return "The encrypted item was not bound to the expected security key."
	case "invalid_grant":
		return "The authorization code, redirect URI, or PKCE verifier was rejected."
	case "session_expired":
		return "Your session expired. Please start again."
	case "invalid_id":
		return "The item ID was invalid."
	case "id_already_exists":
		return "That item ID already exists. Please try again."
	case "invalid_item_type":
		return "The item type was invalid."
	case "invalid_key":
		return "The encryption key was invalid."
	case "invalid_ciphertext":
		return "The encrypted payload was invalid."
	case "payload_too_large":
		return "The encrypted payload is too large."
	case "invalid_cipher_nonce":
		return "The encryption nonce was invalid."
	case "unsupported_cipher_algorithm":
		return "The selected encryption algorithm is not supported."
	case "missing_wrapped_dek":
		return "The wrapped encryption key was missing."
	case "mime_type_not_allowed":
		return "That file type is not allowed."
	case "unable_to_create_key_verifier":
		return "The server could not prepare the item encryption verifier."
	case "unable_to_store_item":
		return "The server could not store the Cryptbin item."
	case "unable_to_wrap_dek":
		return "The server could not protect the item encryption key."
	case "unable_to_unwrap_dek":
		return "The server could not recover the item encryption key."
	case "cryptbin_unavailable":
		return "Encrypted item key wrapping is not configured on this server."
	case "webauthn_verification_failed":
		return "The security key response could not be verified."
	case "forbidden":
		return "You are not allowed to perform that action."
	case "not_found":
		return "The requested item was not found."
	case "internal_error":
		return "An internal server error occurred."
	default:
		return err
	}
}
