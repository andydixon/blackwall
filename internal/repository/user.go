// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package repository

import (
	"database/sql"

	"blackwall/internal/model"
)

type UserRepository struct{ db *sql.DB }

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

const userSelect = `SELECT id, organization_id, uuid, display_label, status, created_at, updated_at FROM users`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	u := &model.User{}
	err := row.Scan(&u.ID, &u.OrganizationID, &u.UUID, &u.DisplayLabel, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepository) FindByID(id int) (*model.User, error) {
	row := r.db.QueryRow(userSelect+` WHERE id = ?`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (r *UserRepository) FindByUUID(uuid string) (*model.User, error) {
	row := r.db.QueryRow(userSelect+` WHERE uuid = ?`, uuid)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (r *UserRepository) FindAll() ([]*model.User, error) {
	rows, err := r.db.Query(userSelect + ` ORDER BY display_label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (r *UserRepository) FindByOrganization(orgID int) ([]*model.User, error) {
	rows, err := r.db.Query(userSelect+` WHERE organization_id = ? ORDER BY display_label`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (r *UserRepository) Create(orgID int, uuid, displayLabel string) (*model.User, error) {
	_, err := r.db.Exec(`INSERT INTO users (organization_id, uuid, display_label, status) VALUES (?, ?, ?, 'active')`,
		orgID, uuid, displayLabel)
	if err != nil {
		return nil, err
	}
	return r.FindByUUID(uuid)
}

func (r *UserRepository) Update(id int, displayLabel, status string) error {
	_, err := r.db.Exec(`UPDATE users SET display_label=?, status=?, updated_at=NOW() WHERE id=?`, displayLabel, status, id)
	return err
}

func (r *UserRepository) Delete(id int) error {
	_, err := r.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}
