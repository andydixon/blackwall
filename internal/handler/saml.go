package handler

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/config"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

// SAML IdP HTTP handlers. The flow is:
//
//   1. Browser hits /saml/projects/{projectUuid}/sso with a SAMLRequest
//      (either ?SAMLRequest=... for Redirect binding or POSTed for POST).
//   2. We parse the AuthnRequest, look up the SP by entity_id, and stash
//      the (sp_public_id, request_id, relay_state, ACS URL) in the session.
//   3. If the user isn't logged in, redirect them through the standard
//      /portal/login flow. After login, they're sent back here.
//   4. We build a signed SAML Response and render the auto-posting HTML.
//
// We don't enforce signed AuthnRequests — most SaaS apps don't sign theirs,
// and the security boundary that matters is the SP-side verification of OUR
// response, which IS always signed.

// SAMLMetadata returns the IdP EntityDescriptor for a project. Service
// Providers download this once at config time. The metadata URL is
// project-scoped so different customers get different signing certs if you
// later split keys per tenant.
func (h *AdminHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	projectUUID := chi.URLParam(r, "projectUuid")
	var projectID int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=? AND status='active'`, projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}
	cfg := config.Get()
	issuer := strings.TrimRight(cfg.AppURL, "/") + "/saml/projects/" + projectUUID
	sso := issuer + "/sso"
	doc, err := h.App.SAML.IdPMetadata(issuer, sso)
	if err != nil {
		http.Error(w, "metadata: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(doc)
}

// SAMLSSO consumes an AuthnRequest. Supports both HTTP-Redirect (GET) and
// HTTP-POST bindings. Either parses the request, stashes context, and
// either dispatches the user to log in or immediately mints a response if
// they already have an active portal session.
func (h *AdminHandler) SAMLSSO(w http.ResponseWriter, r *http.Request) {
	projectUUID := chi.URLParam(r, "projectUuid")
	var projectID int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=? AND status='active'`, projectUUID).Scan(&projectID)
	if projectID == 0 {
		http.NotFound(w, r)
		return
	}

	// Pull SAMLRequest from query (Redirect) or form (POST).
	deflated := r.Method == http.MethodGet
	var samlReq, relayState string
	if r.Method == http.MethodGet {
		samlReq = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad_request", 400)
			return
		}
		samlReq = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	}
	if samlReq == "" {
		http.Error(w, "missing SAMLRequest", 400)
		return
	}
	authn, err := service.ParseAuthnRequest(samlReq, deflated)
	if err != nil {
		http.Error(w, "parse: "+err.Error(), 400)
		return
	}
	sp, err := h.App.SAML.GetSPByEntityID(projectID, authn.Issuer)
	if err != nil {
		http.Error(w, "unknown service provider: "+authn.Issuer, 400)
		return
	}
	if sp.Status != "active" {
		http.Error(w, "service provider disabled", 403)
		return
	}
	// If the AuthnRequest's ACS URL is present, it must match the registered
	// one — otherwise an attacker could request that we POST our signed
	// response to their server. The spec leaves this optional; we enforce.
	if authn.AssertionConsumerServiceURL != "" && authn.AssertionConsumerServiceURL != sp.ACSURL {
		http.Error(w, "acs_url mismatch", 400)
		return
	}

	// Stash the in-flight request in the session so login can pick it up.
	sess, _ := security.GetSession(w, r)
	sess.Set("saml_sp_public_id", sp.PublicID)
	sess.Set("saml_request_id", authn.ID)
	sess.Set("saml_relay_state", relayState)
	sess.Save()

	// If already authenticated to the portal, finish immediately.
	if uid := sess.GetInt("user_id"); uid > 0 {
		h.finalizeSAMLResponse(w, r, uid)
		return
	}
	// Otherwise, hand off to the portal login. After login the portal
	// handler checks for the saml_request_id and bounces back here.
	redirect(w, r, "/portal/login?return_to=/saml/projects/"+projectUUID+"/sso/continue")
}

// SAMLSSOContinue is the post-login bounce target. The portal redirects
// here with a fresh session; we read the stashed AuthnRequest, mint a
// response, and render the auto-posting HTML.
func (h *AdminHandler) SAMLSSOContinue(w http.ResponseWriter, r *http.Request) {
	sess, _ := security.GetSession(w, r)
	uid := sess.GetInt("user_id")
	if uid == 0 {
		redirect(w, r, "/portal/login")
		return
	}
	h.finalizeSAMLResponse(w, r, uid)
}

func (h *AdminHandler) finalizeSAMLResponse(w http.ResponseWriter, r *http.Request, userID int) {
	sess, _ := security.GetSession(w, r)
	spPublicID := sess.GetString("saml_sp_public_id")
	requestID := sess.GetString("saml_request_id")
	relayState := sess.GetString("saml_relay_state")
	if spPublicID == "" || requestID == "" {
		http.Error(w, "no in-flight SAML request", 400)
		return
	}
	sp, err := h.App.SAML.GetSP(spPublicID)
	if err != nil {
		http.Error(w, "sp lookup: "+err.Error(), 500)
		return
	}
	// Verify the user is assigned to this SP's project.
	var assigned int
	h.DB.QueryRow(`SELECT 1 FROM user_project_roles WHERE user_id=? AND project_id=? LIMIT 1`,
		userID, sp.ProjectID).Scan(&assigned)
	if assigned != 1 {
		http.Error(w, "user is not assigned to this project", 403)
		return
	}

	var uuid, label string
	h.DB.QueryRow(`SELECT uuid, display_label FROM users WHERE id=?`, userID).Scan(&uuid, &label)

	cfg := config.Get()
	projectUUID := ""
	h.DB.QueryRow(`SELECT uuid FROM projects WHERE id=?`, sp.ProjectID).Scan(&projectUUID)
	issuer := strings.TrimRight(cfg.AppURL, "/") + "/saml/projects/" + projectUUID

	// Project the user's attributes through the SP's attribute_map. We use
	// the display_label as the source for all mapped attributes for now —
	// custom mappings to oidc claim fields can be layered on later.
	attrs := map[string]string{}
	for samlAttr, source := range sp.AttributeMap {
		switch source {
		case "display_label", "email", "preferred_username":
			attrs[samlAttr] = label
		default:
			// Look up the source in the OIDC claims store so SAML
			// attribute_map can reference custom claims like "department".
			if h.App.Claims != nil {
				merged, _ := h.App.Claims.MergedClaims(userID, sp.ProjectID)
				if v, ok := merged[source]; ok {
					attrs[samlAttr] = anyToString(v)
				}
			}
		}
	}

	respXML, err := h.App.SAML.BuildResponse(&service.ResponseInput{
		SP:           sp,
		InResponseTo: requestID,
		UserUUID:     uuid,
		UserEmail:    label,
		UserAttrs:    attrs,
		IssuerURL:    issuer,
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotOnOrAfter: time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		http.Error(w, "build response: "+err.Error(), 500)
		return
	}

	// Audit the issuance.
	if audit := getAudit(r); audit != nil {
		audit.LogSuccess("saml.response.issued", service.AuditMeta{
			"actor_user_id":   userID,
			"project_id":      sp.ProjectID,
			"project_uuid":    projectUUID,
			"target_type":     "saml_service_provider",
			"target_id":       int64(sp.ID),
			"sp_entity_id":    sp.EntityID,
		})
	}

	// Clear the stashed request so a refresh doesn't replay.
	sess.Delete("saml_sp_public_id")
	sess.Delete("saml_request_id")
	sess.Delete("saml_relay_state")
	sess.Save()

	// Render the auto-posting form.
	encoded := base64.StdEncoding.EncodeToString(respXML)
	page := service.PostBindingHTML(sp.ACSURL, encoded, relayState)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(page)
}

func anyToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// ─── Admin UI: SAML SP registry ────────────────────────────────────────────

// SAMLSPList renders the per-project SP registry.
func (h *AdminHandler) SAMLSPList(w http.ResponseWriter, r *http.Request) {
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
	h.DB.QueryRow(`SELECT id, name FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID, &projectName)
	sps, _ := h.App.SAML.ListSPsForProject(projectID)

	cfg := config.Get()
	metadataURL := strings.TrimRight(cfg.AppURL, "/") + "/saml/projects/" + projectUUID + "/metadata"
	ssoURL := strings.TrimRight(cfg.AppURL, "/") + "/saml/projects/" + projectUUID + "/sso"

	data := h.adminBaseData(w, r, "SAML SPs: "+projectName)
	data["Project"] = map[string]interface{}{"UUID": projectUUID, "Name": projectName, "ID": projectID}
	data["SPs"] = sps
	data["MetadataURL"] = metadataURL
	data["SSOUrl"] = ssoURL
	data["CanManage"] = security.HasCapability(scope.AdminRole, "manage_projects")
	data["Success"] = r.URL.Query().Get("success")
	data["Error"] = r.URL.Query().Get("error")
	templates.AdminPage(w, "projects/saml.html", data)
}

// SAMLSPCreate registers a new SP.
func (h *AdminHandler) SAMLSPCreate(w http.ResponseWriter, r *http.Request) {
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
		redirect(w, r, "/admin/projects/"+projectUUID+"/saml?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/saml?error=csrf")
		return
	}
	var projectID int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, projectUUID).Scan(&projectID)
	attrMap := parseAttrMap(r.FormValue("attribute_map"))
	sp, err := h.App.SAML.CreateSP(projectID,
		strings.TrimSpace(r.FormValue("entity_id")),
		strings.TrimSpace(r.FormValue("acs_url")),
		strings.TrimSpace(r.FormValue("slo_url")),
		strings.TrimSpace(r.FormValue("name_id_format")),
		strings.TrimSpace(r.FormValue("audience")),
		attrMap,
		strings.TrimSpace(r.FormValue("sp_cert_pem")))
	if err != nil {
		audit.LogFail("admin.saml.sp.create.fail", service.AuditMeta{"actor_user_id": actorID, "failure_reason": err.Error()})
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/saml?error=invalid")
		return
	}
	audit.LogSuccess("admin.saml.sp.create", service.AuditMeta{
		"actor_user_id": actorID,
		"project_id":    projectID,
		"target_type":   "saml_service_provider",
		"target_id":     int64(sp.ID),
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/saml?success=created")
}

// SAMLSPDelete removes a registered SP.
func (h *AdminHandler) SAMLSPDelete(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.requireAdminAuth(w, r)
	if !ok {
		return
	}
	if !h.requireCapability(w, r, "manage_projects") {
		return
	}
	scope := h.scopeFor(r)
	projectUUID := chi.URLParam(r, "projectUuid")
	publicID := chi.URLParam(r, "spId")
	audit := getAudit(r)
	if !scope.CanAccessProjectUUID(projectUUID) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/admin/projects/"+projectUUID+"/saml?error=bad_request")
		return
	}
	sess, _ := security.GetSession(w, r)
	if !security.ValidateCSRF(sess, r.FormValue("csrf_token")) {
		sess.Save()
		redirect(w, r, "/admin/projects/"+projectUUID+"/saml?error=csrf")
		return
	}
	_ = h.App.SAML.DeleteSP(publicID)
	audit.LogSuccess("admin.saml.sp.delete", service.AuditMeta{
		"actor_user_id": actorID,
		"target_type":   "saml_service_provider",
	})
	sess.Save()
	redirect(w, r, "/admin/projects/"+projectUUID+"/saml?success=deleted")
}

// parseAttrMap turns the form's "saml_attr=source\nsaml_attr2=source2"
// textarea into a map. Empty lines and lines without `=` are skipped.
func parseAttrMap(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if k != "" && v != "" {
			// URL-decode the key in case the admin pasted a long
			// namespaced one (e.g. ms-claim URIs).
			if dec, err := url.QueryUnescape(k); err == nil {
				k = dec
			}
			m[k] = v
		}
	}
	return m
}
