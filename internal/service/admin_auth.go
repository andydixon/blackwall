package service

import (
	"database/sql"
)

type AdminAuthService struct {
	db *sql.DB
}

func NewAdminAuthService(db *sql.DB) *AdminAuthService {
	return &AdminAuthService{db: db}
}

type AdminRole struct {
	UserID int
	Role   string
}

func (s *AdminAuthService) GetRole(userID int) (string, error) {
	// Check admin_roles table
	var role string
	var isActive bool
	err := s.db.QueryRow(`SELECT role, is_active FROM admin_roles WHERE user_id=?`, userID).Scan(&role, &isActive)
	if err == sql.ErrNoRows {
		// Fallback: check if any admin_roles exist at all
		var count int
		s.db.QueryRow(`SELECT COUNT(*) FROM admin_roles WHERE is_active=TRUE`).Scan(&count)
		if count == 0 {
			// No roles configured — all admins are super_admin (legacy mode)
			if s.isAdminProjectMember(userID) {
				return "super_admin", nil
			}
			return "", nil
		}
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !isActive {
		return "", nil
	}
	return role, nil
}

func (s *AdminAuthService) IsSuperAdmin(userID int) bool {
	role, err := s.GetRole(userID)
	if err != nil {
		return false
	}
	return role == "super_admin"
}

func (s *AdminAuthService) IsAdmin(userID int) bool {
	role, err := s.GetRole(userID)
	return err == nil && role != ""
}

func (s *AdminAuthService) isAdminProjectMember(userID int) bool {
	// Check if user has a role in the admin project
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM user_project_roles upr
		JOIN projects p ON p.id=upr.project_id
		WHERE upr.user_id=? AND p.name='BlackWall Admin' AND p.status='active'`, userID).Scan(&count)
	return count > 0
}

func (s *AdminAuthService) UpsertRole(userID int, role string) error {
	_, err := s.db.Exec(`INSERT INTO admin_roles (user_id, role, is_active) VALUES (?,?,TRUE)
		ON CONFLICT (user_id) DO UPDATE SET role=EXCLUDED.role, is_active=TRUE`, userID, role)
	return err
}

func (s *AdminAuthService) RevokeRole(userID int) error {
	_, err := s.db.Exec(`UPDATE admin_roles SET is_active=FALSE WHERE user_id=?`, userID)
	return err
}

func (s *AdminAuthService) ListRoles() ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT ar.user_id, ar.role, ar.is_active, u.display_label, u.uuid
		FROM admin_roles ar JOIN users u ON u.id=ar.user_id ORDER BY ar.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var userID int
		var role, label, uuid string
		var active bool
		if err := rows.Scan(&userID, &role, &active, &label, &uuid); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"user_id": userID,
			"role":    role,
			"active":  active,
			"label":   label,
			"uuid":    uuid,
		})
	}
	return result, nil
}
