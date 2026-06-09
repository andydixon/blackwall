package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/config"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

type CryptbinHandler struct {
	App      *App
	Storage  *service.CryptbinStorage
	KEK      *service.CryptbinKEK
	WebAuthn *service.WebAuthnService
}

func (h *CryptbinHandler) CreateForm(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	csrf := security.GenerateCSRF(sess)
	sess.Save()
	cfg := config.Get()
	templates.Standalone(w, "cryptbin/create.html", map[string]interface{}{
		"CSRFToken":      csrf,
		"MaxUploadBytes": cfg.CryptbinMaxUploadBytes,
		"MaxTextBytes":   cfg.CryptbinMaxTextBytes,
	})
}

func (h *CryptbinHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	type requestData struct {
		form map[string]string
		json map[string]json.RawMessage
	}
	body := requestData{form: map[string]string{}}
	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if isJSON {
		if err := json.NewDecoder(r.Body).Decode(&body.json); err != nil {
			jsonError(w, "bad_request", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			jsonError(w, "bad_request", http.StatusBadRequest)
			return
		}
		for k := range r.Form {
			body.form[k] = r.FormValue(k)
		}
	}
	getField := func(key string) string {
		if isJSON {
			return jsonStrField(body.json, key)
		}
		return body.form[key]
	}

	if !security.ValidateCSRF(sess, getField("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.create"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := getField("id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "invalid_id", http.StatusBadRequest)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.create", 8, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}
	if !h.App.RateLimit.Check("id:"+id, "cryptbin.create", 3, 300) {
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	if h.Storage.Exists(id) {
		jsonError(w, "id_already_exists", http.StatusConflict)
		return
	}

	itemType := getField("item_type")
	if itemType != "text" && itemType != "file" {
		jsonError(w, "invalid_item_type", http.StatusBadRequest)
		return
	}

	keyB64 := getField("key_b64url")
	if !service.CryptbinValidateKeyMaterial(keyB64) {
		jsonError(w, "invalid_key", http.StatusBadRequest)
		return
	}

	ciphertextB64 := getField("ciphertext_b64url")
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextB64)
	if err != nil || len(ciphertext) == 0 {
		jsonError(w, "invalid_ciphertext", http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	if int64(len(ciphertext)) > cfg.CryptbinMaxUploadBytes {
		jsonError(w, "payload_too_large", http.StatusRequestEntityTooLarge)
		return
	}

	nonceB64 := getField("cipher_nonce_b64url")
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceB64)
	if len(nonce) != 12 {
		jsonError(w, "invalid_cipher_nonce", http.StatusBadRequest)
		return
	}

	cipherAlg := getField("cipher_alg")
	if cipherAlg != "AES-256-GCM" {
		jsonError(w, "unsupported_cipher_algorithm", http.StatusBadRequest)
		return
	}

	wrappedDEK := getField("wrapped_dek")
	wrappedDEKNonce := getField("wrapped_dek_nonce")
	wrappedDEKAlg := getField("wrapped_dek_alg")
	kekVersion := getField("kek_version")
	if wrappedDEK == "" || wrappedDEKNonce == "" || wrappedDEKAlg == "" || kekVersion == "" {
		jsonError(w, "missing_wrapped_dek", http.StatusBadRequest)
		return
	}

	mimeType := getField("mime_type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	if !service.AllowedMimeType(mimeType) {
		jsonError(w, "mime_type_not_allowed", http.StatusBadRequest)
		return
	}

	filename := h.Storage.SanitizeFilename(getField("original_filename"), itemType)
	verifier, err := service.CryptbinCreateVerifier(keyB64)
	if err != nil {
		log.Printf("cryptbin create verifier failed: id=%q err=%v", id, err)
		jsonError(w, "unable_to_create_key_verifier", http.StatusInternalServerError)
		return
	}

	boundCredID := 0
	if isJSON {
		boundCredID = jsonIntField(body.json, "webauthn_credential_id")
	} else {
		boundCredID = parseInt(getField("webauthn_credential_id"))
	}
	boundCredPublicID := getField("webauthn_credential_public_id")
	if (boundCredID > 0) != (boundCredPublicID != "") {
		jsonError(w, "invalid_credential_binding", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	meta := &service.CryptbinMeta{
		ID:                      id,
		Version:                 1,
		ItemType:                itemType,
		OriginalFilename:        filename,
		MimeType:                mimeType,
		CipherAlg:               cipherAlg,
		CipherNonceB64URL:       base64.RawURLEncoding.EncodeToString(nonce),
		WrappedDEK:              wrappedDEK,
		WrappedDEKNonce:         wrappedDEKNonce,
		WrappedDEKAlg:           wrappedDEKAlg,
		KEKVersion:              kekVersion,
		Verifier:                verifier,
		CreatedAt:               now,
		UpdatedAt:               now,
		RequiresWebAuthnForView: true,
	}
	if boundCredID > 0 {
		meta.WebAuthnCredentialID = boundCredID
		meta.WebAuthnCredentialPublicID = boundCredPublicID
	}
	if cfg.CryptbinDefaultRetentionDays > 0 {
		meta.ExpiresAt = time.Now().Add(time.Duration(cfg.CryptbinDefaultRetentionDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}

	if err := h.Storage.WriteItem(id, meta, ciphertext); err != nil {
		log.Printf("cryptbin write failed: id=%q path=%q err=%v", id, h.Storage.BasePath(), err)
		jsonError(w, "unable_to_store_item", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("cryptbin.create.success", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()
	jsonOK(w, map[string]interface{}{"success": true, "id": id, "url": "/cryptbin/" + id, "csrf_token": nextCSRF})
}

func (h *CryptbinHandler) View(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		http.NotFound(w, r)
		return
	}
	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		http.NotFound(w, r)
		return
	}

	sess, _ := security.GetSession(w, r)
	csrf := security.GenerateCSRF(sess)
	sess.Save()
	cfg := config.Get()
	templates.Standalone(w, "cryptbin/view.html", map[string]interface{}{
		"CSRFToken":      csrf,
		"ID":             id,
		"MaxUploadBytes": cfg.CryptbinMaxUploadBytes,
		"MaxTextBytes":   cfg.CryptbinMaxTextBytes,
	})
}

func (h *CryptbinHandler) Share(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		http.NotFound(w, r)
		return
	}
	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		http.NotFound(w, r)
		return
	}
	templates.Standalone(w, "cryptbin/share.html", map[string]interface{}{"ID": id})
}

func (h *CryptbinHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	audit := getAudit(r)
	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "not_found", http.StatusNotFound)
		return
	}
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.metadata", 60, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}
	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		jsonError(w, "not_found", http.StatusNotFound)
		return
	}
	jsonOK(w, h.Storage.PublicMeta(meta))
}

func (h *CryptbinHandler) Ciphertext(w http.ResponseWriter, r *http.Request) {
	audit := getAudit(r)
	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		http.NotFound(w, r)
		return
	}
	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.ciphertext", 60, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}
	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		http.NotFound(w, r)
		return
	}
	ct, err := h.Storage.ReadCiphertext(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(ct)
}

func (h *CryptbinHandler) WebAuthnChallenge(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	type requestData struct {
		form map[string]string
		json map[string]json.RawMessage
	}
	body := requestData{form: map[string]string{}}
	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if isJSON {
		if err := json.NewDecoder(r.Body).Decode(&body.json); err != nil {
			jsonError(w, "bad_request", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			jsonError(w, "bad_request", http.StatusBadRequest)
			return
		}
		for k := range r.Form {
			body.form[k] = r.FormValue(k)
		}
	}
	getField := func(key string) string {
		if isJSON {
			return jsonStrField(body.json, key)
		}
		return body.form[key]
	}

	if !security.ValidateCSRF(sess, getField("csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.challenge"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	op := getField("op")
	if !h.Storage.ValidateID(id) || !isAllowedOp(op) {
		jsonError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	if op != "wrap_create" {
		meta, err := h.Storage.ReadMeta(id)
		if err != nil || h.Storage.IsExpired(meta) {
			jsonError(w, "not_found", http.StatusNotFound)
			return
		}
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.webauthn.challenge", 20, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	ops, _ := sess.Get("cryptbin_webauthn_ops").(map[string]interface{})
	if ops == nil {
		ops = map[string]interface{}{}
	}
	ops[nonce] = map[string]interface{}{
		"id":         id,
		"op":         op,
		"challenge":  challengeB64,
		"expires_at": time.Now().Add(120 * time.Second).Unix(),
	}
	sess.Set("cryptbin_webauthn_ops", ops)
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]interface{}{
		"nonce":      nonce,
		"csrf_token": nextCSRF,
		"publicKey": map[string]interface{}{
			"challenge":        challengeB64,
			"timeout":          60000,
			"rpId":             h.WebAuthn.RPID(),
			"userVerification": "required",
		},
		"expires_in_seconds": 120,
	})
}

func (h *CryptbinHandler) Wrap(w http.ResponseWriter, r *http.Request) {
	if h.KEK == nil {
		jsonError(w, "cryptbin_unavailable", http.StatusServiceUnavailable)
		return
	}
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	if !security.ValidateCSRF(sess, jsonStrField(body, "csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.wrap"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "invalid_id", http.StatusBadRequest)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.wrap", 12, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	if jsonStrField(body, "op") != "wrap_create" {
		jsonError(w, "invalid_operation", http.StatusBadRequest)
		return
	}

	credID, credDBID, ok := h.verifyOperationAssertion(sess, body, id, "wrap_create")
	if !ok {
		audit.LogFail("cryptbin.wrap.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "WebAuthn verification failed"})
		sess.Save()
		jsonError(w, "webauthn_verification_failed", http.StatusForbidden)
		return
	}

	dekB64 := jsonStrField(body, "dek_b64url")
	dek, err := base64.RawURLEncoding.DecodeString(dekB64)
	if err != nil || len(dek) != 32 {
		jsonError(w, "invalid_dek", http.StatusBadRequest)
		return
	}

	wrapped, err := h.KEK.WrapDEK(dek, id)
	if err != nil {
		log.Printf("cryptbin wrap failed: id=%q err=%v", id, err)
		jsonError(w, "unable_to_wrap_dek", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("cryptbin.wrap.success", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credID})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]interface{}{
		"success":                       true,
		"csrf_token":                    nextCSRF,
		"wrapped":                       wrapped,
		"webauthn_credential_id":        credDBID,
		"webauthn_credential_public_id": credID,
	})
}

func (h *CryptbinHandler) Unwrap(w http.ResponseWriter, r *http.Request) {
	if h.KEK == nil {
		jsonError(w, "cryptbin_unavailable", http.StatusServiceUnavailable)
		return
	}
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	if !security.ValidateCSRF(sess, jsonStrField(body, "csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.unwrap"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "invalid_id", http.StatusBadRequest)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.unwrap", 20, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		jsonError(w, "not_found", http.StatusNotFound)
		return
	}

	keyB64 := jsonStrField(body, "key_b64url")
	if !service.CryptbinVerifyKey(keyB64, meta.Verifier) {
		audit.LogFail("cryptbin.unwrap.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Invalid key"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	credID, credDBID, ok := h.verifyOperationAssertion(sess, body, id, "unwrap_view")
	if !ok {
		audit.LogFail("cryptbin.unwrap.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "WebAuthn verification failed"})
		sess.Save()
		jsonError(w, "webauthn_verification_failed", http.StatusForbidden)
		return
	}

	if meta.WebAuthnCredentialPublicID != "" && meta.WebAuthnCredentialPublicID != credID {
		audit.LogFail("cryptbin.unwrap.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Credential binding mismatch"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	dek, err := h.KEK.UnwrapDEK(meta, id)
	if err != nil {
		audit.LogFail("cryptbin.unwrap.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Failed to unwrap DEK"})
		sess.Save()
		jsonError(w, "unable_to_unwrap_dek", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("cryptbin.unwrap.success", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credID})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()

	jsonOK(w, map[string]interface{}{"success": true, "dek_b64url": base64.RawURLEncoding.EncodeToString(dek), "csrf_token": nextCSRF})
}

func (h *CryptbinHandler) Update(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	if !security.ValidateCSRF(sess, jsonStrField(body, "csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.update"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "invalid_id", http.StatusBadRequest)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.update", 10, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		jsonError(w, "not_found", http.StatusNotFound)
		return
	}

	keyB64 := jsonStrField(body, "key_b64url")
	if !service.CryptbinVerifyKey(keyB64, meta.Verifier) {
		audit.LogFail("cryptbin.update.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Invalid key"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	credID, credDBID, ok := h.verifyOperationAssertion(sess, body, id, "update")
	if !ok {
		audit.LogFail("cryptbin.update.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "WebAuthn verification failed"})
		sess.Save()
		jsonError(w, "webauthn_verification_failed", http.StatusForbidden)
		return
	}

	if meta.WebAuthnCredentialPublicID != "" && meta.WebAuthnCredentialPublicID != credID {
		audit.LogFail("cryptbin.update.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Credential binding mismatch"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	itemType := jsonStrField(body, "item_type")
	if itemType != "text" && itemType != "file" {
		jsonError(w, "invalid_item_type", http.StatusBadRequest)
		return
	}

	ciphertextB64 := jsonStrField(body, "ciphertext_b64url")
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextB64)
	if err != nil || len(ciphertext) == 0 {
		jsonError(w, "invalid_ciphertext", http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	if int64(len(ciphertext)) > cfg.CryptbinMaxUploadBytes {
		jsonError(w, "payload_too_large", http.StatusRequestEntityTooLarge)
		return
	}

	nonceB64 := jsonStrField(body, "cipher_nonce_b64url")
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceB64)
	if len(nonce) != 12 {
		jsonError(w, "invalid_cipher_nonce", http.StatusBadRequest)
		return
	}

	meta.ItemType = itemType
	meta.CipherNonceB64URL = base64.RawURLEncoding.EncodeToString(nonce)
	meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := h.Storage.WriteItem(id, meta, ciphertext); err != nil {
		log.Printf("cryptbin update write failed: id=%q path=%q err=%v", id, h.Storage.BasePath(), err)
		jsonError(w, "unable_to_store_item", http.StatusInternalServerError)
		return
	}

	audit.LogSuccess("cryptbin.update.success", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credID})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()
	jsonOK(w, map[string]interface{}{"success": true, "csrf_token": nextCSRF})
}

func (h *CryptbinHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	audit := getAudit(r)

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad_request", http.StatusBadRequest)
		return
	}

	if !security.ValidateCSRF(sess, jsonStrField(body, "csrf_token")) {
		audit.LogFail("security.csrf.fail", service.AuditMeta{"failure_reason": "cryptbin.delete"})
		sess.Save()
		jsonError(w, "invalid_csrf", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.Storage.ValidateID(id) {
		jsonError(w, "invalid_id", http.StatusBadRequest)
		return
	}

	ip := getIP(r)
	if !h.App.RateLimit.Check("ip:"+ip, "cryptbin.delete", 10, 300) {
		audit.LogFail("security.ratelimit.hit", service.AuditMeta{"target_type": "cryptbin", "target_id": id})
		jsonError(w, "rate_limit_exceeded", http.StatusTooManyRequests)
		return
	}

	meta, err := h.Storage.ReadMeta(id)
	if err != nil || h.Storage.IsExpired(meta) {
		jsonError(w, "not_found", http.StatusNotFound)
		return
	}

	keyB64 := jsonStrField(body, "key_b64url")
	if !service.CryptbinVerifyKey(keyB64, meta.Verifier) {
		audit.LogFail("cryptbin.delete.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Invalid key"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	credID, credDBID, ok := h.verifyOperationAssertion(sess, body, id, "delete")
	if !ok {
		audit.LogFail("cryptbin.delete.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "WebAuthn verification failed"})
		sess.Save()
		jsonError(w, "webauthn_verification_failed", http.StatusForbidden)
		return
	}

	if meta.WebAuthnCredentialPublicID != "" && meta.WebAuthnCredentialPublicID != credID {
		audit.LogFail("cryptbin.delete.fail", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "failure_reason": "Credential binding mismatch"})
		sess.Save()
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	h.Storage.DeleteItem(id)
	audit.LogSuccess("cryptbin.delete.success", service.AuditMeta{"target_type": "cryptbin", "target_id": id, "webauthn_credential_id": credDBID, "webauthn_credential_public_id": credID})
	nextCSRF := security.GenerateCSRF(sess)
	sess.Save()
	jsonOK(w, map[string]interface{}{"success": true, "csrf_token": nextCSRF})
}

// verifyOperationAssertion validates a WebAuthn assertion stored in session for a specific op.
func (h *CryptbinHandler) verifyOperationAssertion(sess *security.Session, body map[string]json.RawMessage, id, expectedOp string) (credentialPublicID string, credentialDBID int, ok bool) {
	nonce := jsonStrField(body, "nonce")
	if nonce == "" {
		return "", 0, false
	}

	ops, _ := sess.Get("cryptbin_webauthn_ops").(map[string]interface{})
	if ops == nil {
		return "", 0, false
	}
	opData, exists := ops[nonce]
	if !exists {
		return "", 0, false
	}
	opMap, _ := opData.(map[string]interface{})
	if opMap == nil {
		return "", 0, false
	}
	delete(ops, nonce)
	sess.Set("cryptbin_webauthn_ops", ops)

	opID, _ := opMap["id"].(string)
	op, _ := opMap["op"].(string)
	challenge, _ := opMap["challenge"].(string)
	expiresAt, _ := opMap["expires_at"].(int64)

	if opID != id || op != expectedOp || challenge == "" {
		return "", 0, false
	}
	if expiresAt > 0 && time.Now().Unix() > expiresAt {
		return "", 0, false
	}

	credID := jsonStrField(body, "id")
	clientDataJSON := jsonNestedStr(body, "response", "clientDataJSON")
	authenticatorData := jsonNestedStr(body, "response", "authenticatorData")
	signature := jsonNestedStr(body, "response", "signature")

	if credID == "" || clientDataJSON == "" || authenticatorData == "" || signature == "" {
		return "", 0, false
	}

	if ok, _ := h.WebAuthn.VerifyAssertionDetailed(credID, clientDataJSON, authenticatorData, signature, challenge); !ok {
		return "", 0, false
	}

	cred, err := h.WebAuthn.GetCredentialByPublicID(credID)
	if err != nil || cred == nil {
		return "", 0, false
	}

	return credID, cred.ID, true
}

func isAllowedOp(op string) bool {
	return op == "wrap_create" || op == "unwrap_view" || op == "update" || op == "delete"
}

func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
