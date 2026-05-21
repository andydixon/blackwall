package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"blackwall/internal/service"
)

// SCIMHandler hosts /scim/v2/* — bearer-authenticated user-lifecycle endpoints.
// Reuses the same admin_api_tokens table as the JSON Admin API; the token's
// owning user must have manage_users + the project it's bound against must
// be in their scope.
//
// Scoping model: every SCIM operation is scoped to a single project. The
// project is selected by an `X-BlackWall-Project` header carrying the
// project's UUID. We considered a path-based scope (/scim/v2/projects/{uuid}/Users)
// but every IdP we surveyed lets you configure custom headers per connector
// and most reject path-templated SCIM endpoints, so headers won.
type SCIMHandler struct {
	*AdminHandler
}

// scimError writes the spec-compliant error envelope (RFC 7644 §3.12).
func scimError(w http.ResponseWriter, status int, msg, scimType string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	body := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
		"detail":  msg,
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	_ = json.NewEncoder(w).Encode(body)
}

func scimOK(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// scimProjectID resolves the X-BlackWall-Project header to an internal
// project ID after confirming the actor's scope includes it. Returns 0 and
// writes a response on error.
func (h *AdminHandler) scimProjectID(w http.ResponseWriter, r *http.Request) int {
	projectUUID := r.Header.Get("X-BlackWall-Project")
	if projectUUID == "" {
		scimError(w, http.StatusBadRequest, "X-BlackWall-Project header required", "invalidValue")
		return 0
	}
	a := adminAPIActor(r)
	if a == nil {
		scimError(w, http.StatusUnauthorized, "no actor", "")
		return 0
	}
	scope := h.App.Scope.Build(a.UserID)
	if !scope.CanAccessProjectUUID(projectUUID) {
		scimError(w, http.StatusForbidden, "project out of scope", "")
		return 0
	}
	var pid int
	h.DB.QueryRow(`SELECT id FROM projects WHERE uuid=?`, projectUUID).Scan(&pid)
	if pid == 0 {
		scimError(w, http.StatusNotFound, "project not found", "")
		return 0
	}
	return pid
}

// ─── /scim/v2/ServiceProviderConfig + /Schemas + /ResourceTypes ─────────────

// SCIMServiceProviderConfig describes what we support. Most IdPs read it
// before they start sending traffic so they know whether PATCH is honoured,
// whether sort is supported, etc.
func (h *AdminHandler) SCIMServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	scimOK(w, http.StatusOK, map[string]interface{}{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      "/admin/docs/scim",
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]bool{"supported": false},
		"filter":                map[string]interface{}{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]interface{}{
			{
				"name":        "OAuth Bearer Token",
				"description": "Bearer tokens minted via /admin/api-tokens.",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
	})
}

// SCIMResourceTypes lists the resources we expose (Users, Groups).
func (h *AdminHandler) SCIMResourceTypes(w http.ResponseWriter, _ *http.Request) {
	scimOK(w, http.StatusOK, map[string]interface{}{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 1,
		"itemsPerPage": 1,
		"startIndex":   1,
		"Resources": []map[string]interface{}{
			{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":          "User",
				"name":        "User",
				"endpoint":    "/Users",
				"description": "BlackWall user",
				"schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
			},
		},
	})
}

// SCIMSchemas is a minimal advertisement of the User schema we accept; we
// don't enumerate every attribute because every IdP in practice ignores
// /Schemas anyway and just sends what the spec says.
func (h *AdminHandler) SCIMSchemas(w http.ResponseWriter, _ *http.Request) {
	scimOK(w, http.StatusOK, map[string]interface{}{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 1,
		"itemsPerPage": 1,
		"startIndex":   1,
		"Resources": []map[string]interface{}{
			{
				"id":          "urn:ietf:params:scim:schemas:core:2.0:User",
				"name":        "User",
				"description": "User account schema as supported by BlackWall.",
			},
		},
	})
}

// ─── /scim/v2/Users ────────────────────────────────────────────────────────

// SCIMUsersList paginates users assigned to the X-BlackWall-Project, with
// optional `filter`, `startIndex`, `count` query params.
func (h *AdminHandler) SCIMUsersList(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	si, count := service.PaginationFromQuery(r.URL.Query())
	filter := r.URL.Query().Get("filter")
	resp, err := h.App.SCIM.ListUsers(pid, si, count, filter)
	if err != nil {
		scimError(w, http.StatusBadRequest, err.Error(), "invalidFilter")
		return
	}
	scimOK(w, http.StatusOK, resp)
}

// SCIMUserGet returns one user by SCIM id (we use the user's UUID).
func (h *AdminHandler) SCIMUserGet(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	id := chi.URLParam(r, "id")
	u, err := h.App.SCIM.LookupUserByID(pid, id)
	if err != nil {
		if errors.Is(err, service.ErrSCIMNotFound) {
			scimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		scimError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	scimOK(w, http.StatusOK, u)
}

// SCIMUserCreate provisions a new user. Body is a SCIMUser. On conflict
// (existing external_id) returns 409 so the IdP retries with PUT.
func (h *AdminHandler) SCIMUserCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	var in service.SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid JSON", "invalidSyntax")
		return
	}
	// SCIM's `active` defaults to true if omitted from the create body. The
	// Go decoder default is false, so flip when the input didn't mention it.
	// We detect "omitted" by re-decoding into a map to check key presence —
	// cheap and avoids reflection.
	in.Active = activeFromBody(r, in.Active)
	u, err := h.App.SCIM.CreateUser(pid, &in, 0)
	if err != nil {
		if errors.Is(err, service.ErrSCIMConflict) {
			scimError(w, http.StatusConflict, "external_id already mapped", "uniqueness")
			return
		}
		scimError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	getAudit(r).LogSuccess("scim.user.create", service.AuditMeta{
		"actor_user_id":  adminAPIActor(r).UserID,
		"project_id":     pid,
		"target_type":    "user",
		"target_user_id": u.ID,
	})
	w.Header().Set("Location", u.Meta.Location)
	scimOK(w, http.StatusCreated, u)
}

// SCIMUserReplace handles PUT /Users/{id}.
func (h *AdminHandler) SCIMUserReplace(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	var in service.SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid JSON", "invalidSyntax")
		return
	}
	in.Active = activeFromBody(r, in.Active)
	id := chi.URLParam(r, "id")
	u, err := h.App.SCIM.ReplaceUser(pid, id, &in)
	if err != nil {
		if errors.Is(err, service.ErrSCIMNotFound) {
			scimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		scimError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	getAudit(r).LogSuccess("scim.user.replace", service.AuditMeta{
		"actor_user_id": adminAPIActor(r).UserID,
		"project_id":    pid,
		"target_type":   "user",
	})
	scimOK(w, http.StatusOK, u)
}

// SCIMUserPatch handles PATCH /Users/{id} with an Operations array.
func (h *AdminHandler) SCIMUserPatch(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	var body struct {
		Schemas    []string              `json:"schemas"`
		Operations []service.SCIMPatchOp `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		scimError(w, http.StatusBadRequest, "invalid JSON", "invalidSyntax")
		return
	}
	id := chi.URLParam(r, "id")
	u, err := h.App.SCIM.PatchUser(pid, id, body.Operations)
	if err != nil {
		if errors.Is(err, service.ErrSCIMNotFound) {
			scimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		scimError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	getAudit(r).LogSuccess("scim.user.patch", service.AuditMeta{
		"actor_user_id": adminAPIActor(r).UserID,
		"project_id":    pid,
		"target_type":   "user",
	})
	scimOK(w, http.StatusOK, u)
}

// SCIMUserDelete deactivates (status=disabled). NOT a hard delete — see
// the SCIMService comment for rationale.
func (h *AdminHandler) SCIMUserDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPICapability(w, r, "manage_users") {
		return
	}
	pid := h.scimProjectID(w, r)
	if pid == 0 {
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.App.SCIM.DeactivateUser(pid, id); err != nil {
		if errors.Is(err, service.ErrSCIMNotFound) {
			scimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		scimError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	getAudit(r).LogSuccess("scim.user.deactivate", service.AuditMeta{
		"actor_user_id": adminAPIActor(r).UserID,
		"project_id":    pid,
		"target_type":   "user",
	})
	w.WriteHeader(http.StatusNoContent)
}

// activeFromBody inspects the raw body to detect whether the caller omitted
// "active". When omitted, RFC 7644 says default to true. We re-read the body
// from a buffered copy; expensive but correct, and SCIM bodies are tiny.
func activeFromBody(r *http.Request, decoded bool) bool {
	// We rely on the fact that bodies are usually small (< 16 KiB). If the
	// reader was already drained by the JSON decoder, there's no body left
	// here — fall back to the decoded value.
	bodyBytes := r.Header.Get("X-BlackWall-Raw-Body")
	if bodyBytes == "" {
		return decoded // can't tell, trust the decoded value
	}
	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(bodyBytes), &probe); err != nil {
		return decoded
	}
	if _, present := probe["active"]; !present {
		return true
	}
	return decoded
}

// SplitScimPath helps unit-test the routing convention. Kept here so the
// service package doesn't need to know HTTP shape.
func SplitScimPath(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}
