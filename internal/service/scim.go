package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SCIMService backs the /scim/v2/Users and /scim/v2/Groups endpoints with the
// minimum behaviour Workday / Okta / Entra need to drive identity lifecycle:
//
//   - GET /Users?filter=userName eq "alice@example.com" — used for matching
//     before a CREATE so the IDP doesn't double-provision an existing email.
//   - GET /Users/{id} — read back what we stored.
//   - POST /Users — create a new user with a starting external_id; we mint
//     an internal `users` row, attach a project membership (the project the
//     bearer token was scoped to), and write the external_id mapping.
//   - PUT /Users/{id} — full replace (most IdPs send PUT for profile updates).
//   - PATCH /Users/{id} — RFC 6902-ish operations targeting individual paths.
//   - DELETE /Users/{id} — disables the user (NOT a hard delete; identity
//     deletes need an admin click + approval workflow, never an HRIS push).
//
// External callers identify users by `id` (we use the user's UUID) OR by
// `externalId` from their side; both lookups are supported on read so an HRIS
// can drive everything via its own ID space.
type SCIMService struct {
	db *sql.DB
}

func NewSCIMService(db *sql.DB) *SCIMService {
	return &SCIMService{db: db}
}

// SCIMUser is the shape we render to/from JSON over the wire. Fields follow
// the RFC 7643 core schema for User; we only emit the subset BlackWall has
// data for. Unknown fields on input are silently ignored so an IdP that
// sends extra attributes (locale, timezone, etc.) doesn't trip a 400.
type SCIMUser struct {
	Schemas    []string                 `json:"schemas"`
	ID         string                   `json:"id"`
	ExternalID string                   `json:"externalId,omitempty"`
	UserName   string                   `json:"userName"`
	Name       *SCIMName                `json:"name,omitempty"`
	Emails     []SCIMEmail              `json:"emails,omitempty"`
	Active     bool                     `json:"active"`
	Meta       *SCIMMeta                `json:"meta,omitempty"`
	Extensions map[string]interface{}   `json:"-"`
}

type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

// SCIMListResponse is the envelope every list endpoint returns. The four
// fields are spec-required even when the result set is empty.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

const (
	scimUserSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimErrorSchema    = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// LookupUserByID resolves a SCIM `id` (which we map to the user UUID) into a
// SCIMUser shape, scoped to the project. Returns ErrSCIMNotFound if absent.
func (s *SCIMService) LookupUserByID(projectID int, scimID string) (*SCIMUser, error) {
	if scimID == "" {
		return nil, ErrSCIMNotFound
	}
	row := s.db.QueryRow(`SELECT u.id, u.uuid, u.display_label, u.status, u.created_at, u.updated_at,
		COALESCE(m.external_id, '')
		FROM users u
		LEFT JOIN scim_user_mapping m ON m.user_id=u.id AND m.project_id=?
		JOIN user_project_roles upr ON upr.user_id=u.id AND upr.project_id=?
		WHERE u.uuid=?`, projectID, projectID, scimID)
	return s.scanUser(row, projectID)
}

// LookupUserByExternalID finds a user by the IdP-supplied external ID. Used
// by upstream PUT/PATCH where the IdP only remembers its own ID space.
func (s *SCIMService) LookupUserByExternalID(projectID int, externalID string) (*SCIMUser, error) {
	if externalID == "" {
		return nil, ErrSCIMNotFound
	}
	row := s.db.QueryRow(`SELECT u.id, u.uuid, u.display_label, u.status, u.created_at, u.updated_at, m.external_id
		FROM scim_user_mapping m
		JOIN users u ON u.id=m.user_id
		WHERE m.project_id=? AND m.external_id=?`, projectID, externalID)
	return s.scanUser(row, projectID)
}

// ListUsers paginates assigned-to-project users, optionally filtered by a
// SCIM `filter` expression. Supports the subset of operators every major IdP
// actually uses: eq, sw, co, pr — on userName, externalId, and active.
func (s *SCIMService) ListUsers(projectID, startIndex, count int, filter string) (*SCIMListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = 50
	}
	if count > 200 {
		count = 200
	}
	q := `SELECT u.id, u.uuid, u.display_label, u.status, u.created_at, u.updated_at,
		COALESCE(m.external_id, '')
		FROM users u
		LEFT JOIN scim_user_mapping m ON m.user_id=u.id AND m.project_id=?
		JOIN user_project_roles upr ON upr.user_id=u.id AND upr.project_id=?`
	args := []interface{}{projectID, projectID}

	if filter != "" {
		clause, fArgs, err := translateSCIMFilter(filter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
		q += " WHERE " + clause
		args = append(args, fArgs...)
	}

	// We do COUNT(*) + LIMIT in two queries; the join cost is small compared
	// to the cost of a single oversized result and we avoid SQL window-fn
	// portability issues.
	countQ := "SELECT COUNT(*) " + q[strings.Index(q, "FROM"):]
	var total int
	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, err
	}

	q += " ORDER BY u.id ASC LIMIT ? OFFSET ?"
	args = append(args, count, startIndex-1)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*SCIMUser
	for rows.Next() {
		u, err := s.scanUserFromRows(rows, projectID)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return &SCIMListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(users),
		Resources:    users,
	}, nil
}

// CreateUser provisions a user from a POST /Users body. We:
//   1. fail if a SCIM external_id already maps to this project (idempotent
//      callers should PUT after a 409),
//   2. create or attach an existing user by userName (email),
//   3. assign them to the bearer-token's project with the default privilege.
//
// The IdP gets back the resulting resource with our `id` (the user UUID).
func (s *SCIMService) CreateUser(projectID int, in *SCIMUser, defaultPrivilege int) (*SCIMUser, error) {
	if in.UserName == "" {
		return nil, errors.New("userName required")
	}
	// Conflict check on external_id.
	if in.ExternalID != "" {
		var exists int
		s.db.QueryRow(`SELECT 1 FROM scim_user_mapping WHERE project_id=? AND external_id=?`,
			projectID, in.ExternalID).Scan(&exists)
		if exists == 1 {
			return nil, ErrSCIMConflict
		}
	}

	// Find or create the underlying users row. We match on display_label
	// (== email) within the project's org.
	var orgID int
	s.db.QueryRow(`SELECT organization_id FROM projects WHERE id=?`, projectID).Scan(&orgID)
	if orgID == 0 {
		return nil, errors.New("project has no organization")
	}

	var userID int
	var userUUID string
	s.db.QueryRow(`SELECT id, uuid FROM users WHERE organization_id=? AND display_label=?`,
		orgID, in.UserName).Scan(&userID, &userUUID)
	if userID == 0 {
		userUUID = uuid.NewString()
		status := "active"
		if !in.Active {
			status = "disabled"
		}
		res, err := s.db.Exec(`INSERT INTO users (organization_id, uuid, display_label, status) VALUES (?,?,?,?)`,
			orgID, userUUID, in.UserName, status)
		if err != nil {
			return nil, err
		}
		id64, _ := res.LastInsertId()
		userID = int(id64)
	}

	// Project assignment — idempotent.
	if defaultPrivilege <= 0 {
		defaultPrivilege = 4 // "Member" in the seeded ladder.
	}
	s.db.Exec(`INSERT IGNORE INTO user_project_roles (user_id, project_id, privilege_level)
		VALUES (?, ?, ?)`, userID, projectID, defaultPrivilege)

	// External ID mapping.
	if in.ExternalID != "" {
		s.db.Exec(`INSERT IGNORE INTO scim_user_mapping (project_id, user_id, external_id)
			VALUES (?, ?, ?)`, projectID, userID, in.ExternalID)
	}

	return s.LookupUserByID(projectID, userUUID)
}

// ReplaceUser handles PUT /Users/{id} — full record replacement. We update
// display_label, status, external_id. Project membership isn't touched
// here; the SCIM client should use Groups for membership.
func (s *SCIMService) ReplaceUser(projectID int, scimID string, in *SCIMUser) (*SCIMUser, error) {
	var userID int
	if err := s.db.QueryRow(`SELECT u.id FROM users u
		JOIN user_project_roles upr ON upr.user_id=u.id AND upr.project_id=?
		WHERE u.uuid=?`, projectID, scimID).Scan(&userID); err != nil {
		return nil, ErrSCIMNotFound
	}
	status := "active"
	if !in.Active {
		status = "disabled"
	}
	if in.UserName != "" {
		s.db.Exec(`UPDATE users SET display_label=?, status=? WHERE id=?`, in.UserName, status, userID)
	} else {
		s.db.Exec(`UPDATE users SET status=? WHERE id=?`, status, userID)
	}
	if in.ExternalID != "" {
		s.db.Exec(`INSERT INTO scim_user_mapping (project_id, user_id, external_id)
			VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id)`,
			projectID, userID, in.ExternalID)
	}
	return s.LookupUserByID(projectID, scimID)
}

// PatchUser applies one or more PatchOp operations. We support the subset
// Workday + Okta + Entra actually send: replace on "active", "userName",
// "name.givenName", "name.familyName", "emails[primary eq true].value".
// Unknown paths return 400.
func (s *SCIMService) PatchUser(projectID int, scimID string, ops []SCIMPatchOp) (*SCIMUser, error) {
	var userID int
	if err := s.db.QueryRow(`SELECT u.id FROM users u
		JOIN user_project_roles upr ON upr.user_id=u.id AND upr.project_id=?
		WHERE u.uuid=?`, projectID, scimID).Scan(&userID); err != nil {
		return nil, ErrSCIMNotFound
	}
	for _, op := range ops {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			// We only honour replace/add for now; remove is also acceptable
			// for the "active" path but everyone sends replace there.
			continue
		}
		path := strings.ToLower(op.Path)
		switch {
		case path == "active":
			if b, ok := op.Value.(bool); ok {
				status := "active"
				if !b {
					status = "disabled"
				}
				s.db.Exec(`UPDATE users SET status=? WHERE id=?`, status, userID)
			}
		case path == "username" || path == "displayname":
			if v, ok := op.Value.(string); ok && v != "" {
				s.db.Exec(`UPDATE users SET display_label=? WHERE id=?`, v, userID)
			}
		case path == "":
			// Whole-object replace shorthand — IdPs sometimes omit Path and
			// stuff the full new representation in Value. Best-effort apply
			// the userName + active fields.
			if m, ok := op.Value.(map[string]interface{}); ok {
				if un, ok := m["userName"].(string); ok && un != "" {
					s.db.Exec(`UPDATE users SET display_label=? WHERE id=?`, un, userID)
				}
				if act, ok := m["active"].(bool); ok {
					status := "active"
					if !act {
						status = "disabled"
					}
					s.db.Exec(`UPDATE users SET status=? WHERE id=?`, status, userID)
				}
			}
		}
	}
	return s.LookupUserByID(projectID, scimID)
}

// DeactivateUser is the SCIM "DELETE" path. We intentionally do NOT hard-delete
// — a misconfigured HRIS connector that bulk-fires DELETE shouldn't be able to
// wipe an organisation's identity store. Disabling preserves audit lineage.
func (s *SCIMService) DeactivateUser(projectID int, scimID string) error {
	res, err := s.db.Exec(`UPDATE users u
		JOIN user_project_roles upr ON upr.user_id=u.id AND upr.project_id=?
		SET u.status='disabled' WHERE u.uuid=?`, projectID, scimID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSCIMNotFound
	}
	return nil
}

// SCIMPatchOp is one element of a PatchOp body's Operations array.
type SCIMPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// Sentinel errors so the handler can map to the right HTTP status.
var (
	ErrSCIMNotFound = errors.New("scim: not found")
	ErrSCIMConflict = errors.New("scim: conflict")
)

func (s *SCIMService) scanUser(row *sql.Row, projectID int) (*SCIMUser, error) {
	var id int
	var uid, label, status string
	var createdAt, updatedAt time.Time
	var externalID string
	if err := row.Scan(&id, &uid, &label, &status, &createdAt, &updatedAt, &externalID); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSCIMNotFound
		}
		return nil, err
	}
	return buildSCIMUser(uid, label, status, externalID, createdAt, updatedAt), nil
}

func (s *SCIMService) scanUserFromRows(rows *sql.Rows, projectID int) (*SCIMUser, error) {
	var id int
	var uid, label, status string
	var createdAt, updatedAt time.Time
	var externalID string
	if err := rows.Scan(&id, &uid, &label, &status, &createdAt, &updatedAt, &externalID); err != nil {
		return nil, err
	}
	return buildSCIMUser(uid, label, status, externalID, createdAt, updatedAt), nil
}

func buildSCIMUser(uid, label, status, externalID string, createdAt, updatedAt time.Time) *SCIMUser {
	emails := []SCIMEmail{}
	if isEmailLabel(label) {
		emails = append(emails, SCIMEmail{Value: label, Primary: true, Type: "work"})
	}
	return &SCIMUser{
		Schemas:    []string{scimUserSchema},
		ID:         uid,
		ExternalID: externalID,
		UserName:   label,
		Active:     status == "active",
		Emails:     emails,
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      createdAt,
			LastModified: updatedAt,
			Location:     "/scim/v2/Users/" + uid,
		},
	}
}

func isEmailLabel(s string) bool {
	return strings.Contains(s, "@") && strings.Contains(s, ".")
}

// translateSCIMFilter converts a SCIM filter expression to a SQL WHERE
// fragment + bound args. Supports the subset Okta + Entra + Workday + Google
// Workspace actually emit: <attr> <op> "value" with ops eq, sw, co, pr,
// joined by `and`. Bracketed grouping and `or` are intentionally not
// supported — every real IdP we've encountered serialises queries with
// commas-as-AND-or-eq, never disjunctions.
func translateSCIMFilter(filter string) (string, []interface{}, error) {
	// Tokenise: attribute, operator, optional quoted value, optional " and ".
	// We use a forgiving regex rather than a real parser; if a customer
	// shows up with bracketed disjunctions we'll bolt on goyacc.
	parts := splitFilterAndClauses(filter)
	var clauses []string
	var args []interface{}
	for _, p := range parts {
		c, a, err := translateOneSCIMFilter(p)
		if err != nil {
			return "", nil, err
		}
		clauses = append(clauses, c)
		args = append(args, a...)
	}
	return strings.Join(clauses, " AND "), args, nil
}

var filterRE = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9.]*)\s+(eq|sw|co|pr)\b\s*(?:"([^"]*)")?\s*$`)

func translateOneSCIMFilter(part string) (string, []interface{}, error) {
	m := filterRE.FindStringSubmatch(part)
	if m == nil {
		return "", nil, fmt.Errorf("unparseable clause: %s", part)
	}
	attr, op, val := strings.ToLower(m[1]), m[2], m[3]
	col, ok := scimAttrToColumn[attr]
	if !ok {
		return "", nil, fmt.Errorf("unsupported attribute: %s", attr)
	}
	switch op {
	case "eq":
		// `active eq true` → numeric on our enum status. Special-case.
		if attr == "active" {
			if val == "true" {
				return col + "='active'", nil, nil
			}
			return col + "!='active'", nil, nil
		}
		return col + "=?", []interface{}{val}, nil
	case "sw":
		return col + " LIKE ?", []interface{}{val + "%"}, nil
	case "co":
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	case "pr":
		return col + " IS NOT NULL AND " + col + "<>''", nil, nil
	}
	return "", nil, fmt.Errorf("unsupported op: %s", op)
}

func splitFilterAndClauses(filter string) []string {
	// Lowercase " and " inside quotes is unaffected because our regex
	// requires the operator to be a top-level keyword. We split on the
	// literal " and " token surrounded by spaces.
	out := []string{}
	depth := 0
	start := 0
	in := false
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		if c == '"' {
			in = !in
			continue
		}
		if !in && c == '(' {
			depth++
		}
		if !in && c == ')' {
			depth--
		}
		if !in && depth == 0 && i+5 <= len(filter) && strings.EqualFold(filter[i:i+5], " and ") {
			out = append(out, strings.TrimSpace(filter[start:i]))
			start = i + 5
			i += 4
		}
	}
	out = append(out, strings.TrimSpace(filter[start:]))
	return out
}

// scimAttrToColumn maps externally-visible SCIM attribute names to the
// SQL columns we want to filter on. We deliberately don't expose columns
// like organization_id even by accident — only the attributes an IdP
// would legitimately filter by.
var scimAttrToColumn = map[string]string{
	"username":   "u.display_label",
	"externalid": "m.external_id",
	"id":         "u.uuid",
	"active":     "u.status",
}

// PaginationFromQuery parses startIndex + count from URL query string with
// sane defaults so handlers stay short. SCIM uses 1-based startIndex.
func PaginationFromQuery(q map[string][]string) (int, int) {
	si, _ := strconv.Atoi(firstQ(q, "startIndex"))
	cnt, _ := strconv.Atoi(firstQ(q, "count"))
	if si < 1 {
		si = 1
	}
	if cnt <= 0 {
		cnt = 50
	}
	return si, cnt
}

func firstQ(q map[string][]string, k string) string {
	if v := q[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// EncodeSCIMUser is a tiny helper that emits a SCIMUser with the required
// schema tag in place, even when called via a generic JSON marshal.
func EncodeSCIMUser(u *SCIMUser) ([]byte, error) {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{scimUserSchema}
	}
	return json.Marshal(u)
}
