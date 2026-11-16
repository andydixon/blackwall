// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package repository

import (
	"database/sql"

	"blackwall/internal/model"
)

type UserProjectRoleRepository struct{ db *sql.DB }

func NewUserProjectRoleRepository(db *sql.DB) *UserProjectRoleRepository {
	return &UserProjectRoleRepository{db: db}
}

func scanRole(row interface{ Scan(...any) error }) (*model.UserProjectRole, error) {
	r := &model.UserProjectRole{}
	return r, row.Scan(&r.ID, &r.UserID, &r.ProjectID, &r.PrivilegeLevel, &r.CreatedAt)
}

func (r *UserProjectRoleRepository) FindByUserAndProject(userID, projectID int) (*model.UserProjectRole, error) {
	row := r.db.QueryRow(`SELECT id, user_id, project_id, privilege_level, created_at FROM user_project_roles WHERE user_id = ? AND project_id = ?`, userID, projectID)
	role, err := scanRole(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return role, err
}

func (r *UserProjectRoleRepository) FindByUser(userID int) ([]*model.UserProjectRole, error) {
	rows, err := r.db.Query(`SELECT id, user_id, project_id, privilege_level, created_at FROM user_project_roles WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoles(rows)
}

func (r *UserProjectRoleRepository) FindByProject(projectID int) ([]*model.UserProjectRole, error) {
	rows, err := r.db.Query(`SELECT id, user_id, project_id, privilege_level, created_at FROM user_project_roles WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoles(rows)
}

func (r *UserProjectRoleRepository) FindByID(id int) (*model.UserProjectRole, error) {
	row := r.db.QueryRow(`SELECT id, user_id, project_id, privilege_level, created_at FROM user_project_roles WHERE id = ?`, id)
	role, err := scanRole(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return role, err
}

func scanRoles(rows *sql.Rows) ([]*model.UserProjectRole, error) {
	var roles []*model.UserProjectRole
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (r *UserProjectRoleRepository) Create(userID, projectID, privilegeLevel int) error {
	_, err := r.db.Exec(`INSERT INTO user_project_roles (user_id, project_id, privilege_level) VALUES (?, ?, ?)`,
		userID, projectID, privilegeLevel)
	return err
}

func (r *UserProjectRoleRepository) Update(id, privilegeLevel int) error {
	_, err := r.db.Exec(`UPDATE user_project_roles SET privilege_level=? WHERE id=?`, privilegeLevel, id)
	return err
}

func (r *UserProjectRoleRepository) Delete(id int) error {
	_, err := r.db.Exec(`DELETE FROM user_project_roles WHERE id=?`, id)
	return err
}
