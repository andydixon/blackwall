package service

import (
	"database/sql"
)

// AdminScope mirrors the PHP getAdminScope() return value: it captures the
// admin role plus the set of organisations and projects the user can act on.
// Used by capability checks (CanAccess*) to gate visibility on every admin
// query that isn't super-admin-only.
type AdminScope struct {
	UserID            int
	IsAdmin           bool
	IsSuperAdmin      bool
	AdminRole         string
	OrganizationIDs   []int
	OrganizationUUIDs []string
	ProjectIDs        []int
	ProjectUUIDs      []string

	orgUUIDSet     map[string]bool
	projectUUIDSet map[string]bool
}

func (s *AdminScope) CanAccessProjectID(id int) bool {
	if s.IsSuperAdmin {
		return true
	}
	for _, p := range s.ProjectIDs {
		if p == id {
			return true
		}
	}
	return false
}

func (s *AdminScope) CanAccessProjectUUID(uuid string) bool {
	if s.IsSuperAdmin {
		return true
	}
	return s.projectUUIDSet[uuid]
}

func (s *AdminScope) CanAccessOrganizationUUID(uuid string) bool {
	if s.IsSuperAdmin {
		return true
	}
	return s.orgUUIDSet[uuid]
}

func (s *AdminScope) CanAccessUserByProjects(userProjectIDs []int) bool {
	if s.IsSuperAdmin {
		return true
	}
	if len(s.ProjectIDs) == 0 {
		return false
	}
	for _, pid := range userProjectIDs {
		for _, sp := range s.ProjectIDs {
			if pid == sp {
				return true
			}
		}
	}
	return false
}

// AdminScopeBuilder loads scope rows from the DB.
type AdminScopeBuilder struct {
	db        *sql.DB
	adminAuth *AdminAuthService
}

func NewAdminScopeBuilder(db *sql.DB, auth *AdminAuthService) *AdminScopeBuilder {
	return &AdminScopeBuilder{db: db, adminAuth: auth}
}

// Build constructs the AdminScope for userID. Returns a zero scope if userID
// is invalid or the user is inactive.
func (b *AdminScopeBuilder) Build(userID int) *AdminScope {
	scope := &AdminScope{
		UserID:         userID,
		orgUUIDSet:     map[string]bool{},
		projectUUIDSet: map[string]bool{},
	}
	if userID < 1 {
		return scope
	}

	var active int
	if err := b.db.QueryRow(`SELECT 1 FROM users WHERE id=? AND status='active' LIMIT 1`, userID).Scan(&active); err != nil || active != 1 {
		return scope
	}

	configuredRole := ""
	if b.adminAuth != nil {
		if r, err := b.adminAuth.GetRole(userID); err == nil {
			switch r {
			case "super_admin", "operator", "auditor":
				configuredRole = r
			}
		}
	}

	isSuperAdmin := configuredRole == "super_admin"

	// Fall back to legacy "super project" detection: a user assigned to a
	// project named/marked as the super-admin project at privilege level 1
	// is treated as super_admin.
	if !isSuperAdmin {
		rows, _ := b.db.Query(`
			SELECT p.uuid, p.name
			FROM user_project_roles upr
			JOIN projects p ON p.id = upr.project_id
			WHERE upr.user_id=? AND upr.privilege_level=1`, userID)
		if rows != nil {
			for rows.Next() {
				var uuid, name string
				_ = rows.Scan(&uuid, &name)
				if isSuperProject(uuid, name) {
					isSuperAdmin = true
					break
				}
			}
			rows.Close()
		}
	}

	if isSuperAdmin {
		// Super admins see every org and project.
		if rows, err := b.db.Query(`SELECT id, uuid FROM organizations`); err == nil {
			for rows.Next() {
				var id int
				var uuid string
				if err := rows.Scan(&id, &uuid); err == nil {
					scope.OrganizationIDs = append(scope.OrganizationIDs, id)
					scope.OrganizationUUIDs = append(scope.OrganizationUUIDs, uuid)
					scope.orgUUIDSet[uuid] = true
				}
			}
			rows.Close()
		}
		if rows, err := b.db.Query(`SELECT id, uuid FROM projects`); err == nil {
			for rows.Next() {
				var id int
				var uuid string
				if err := rows.Scan(&id, &uuid); err == nil {
					scope.ProjectIDs = append(scope.ProjectIDs, id)
					scope.ProjectUUIDs = append(scope.ProjectUUIDs, uuid)
					scope.projectUUIDSet[uuid] = true
				}
			}
			rows.Close()
		}
	} else {
		// Org admins see only the organisations they own and their projects.
		if rows, err := b.db.Query(`SELECT id, uuid FROM organizations WHERE admin_user_id=?`, userID); err == nil {
			for rows.Next() {
				var id int
				var uuid string
				if err := rows.Scan(&id, &uuid); err == nil {
					scope.OrganizationIDs = append(scope.OrganizationIDs, id)
					scope.OrganizationUUIDs = append(scope.OrganizationUUIDs, uuid)
					scope.orgUUIDSet[uuid] = true
				}
			}
			rows.Close()
		}
		if len(scope.OrganizationIDs) > 0 {
			placeholders, args := inClauseInts(scope.OrganizationIDs)
			query := `SELECT id, uuid FROM projects WHERE organization_id IN (` + placeholders + `)`
			if rows, err := b.db.Query(query, args...); err == nil {
				for rows.Next() {
					var id int
					var uuid string
					if err := rows.Scan(&id, &uuid); err == nil {
						scope.ProjectIDs = append(scope.ProjectIDs, id)
						scope.ProjectUUIDs = append(scope.ProjectUUIDs, uuid)
						scope.projectUUIDSet[uuid] = true
					}
				}
				rows.Close()
			}
		}
	}

	hasRoleBased := configuredRole == "super_admin" || configuredRole == "operator" || configuredRole == "auditor"
	scope.IsSuperAdmin = isSuperAdmin
	scope.IsAdmin = isSuperAdmin || hasRoleBased || len(scope.OrganizationIDs) > 0
	if isSuperAdmin {
		scope.AdminRole = "super_admin"
	} else if configuredRole != "" {
		scope.AdminRole = configuredRole
	} else if len(scope.OrganizationIDs) > 0 {
		scope.AdminRole = "operator"
	}

	return scope
}

// isSuperProject mirrors the PHP isSuperProject() heuristic: any project named
// "BlackWall" or with the well-known platform UUID is the super-admin project.
func isSuperProject(uuid, name string) bool {
	if name == "BlackWall" {
		return true
	}
	if uuid == "00000000-0000-0000-0000-000000000001" {
		return true
	}
	return false
}

// inClauseInts builds a "?,?,?,..." placeholder string + arg slice for an IN clause.
func inClauseInts(ids []int) (string, []interface{}) {
	if len(ids) == 0 {
		return "", nil
	}
	placeholders := make([]byte, 0, len(ids)*2-1)
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args[i] = id
	}
	return string(placeholders), args
}
