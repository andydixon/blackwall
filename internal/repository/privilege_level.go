package repository

import (
	"database/sql"

	"blackwall/internal/model"
)

type PrivilegeLevelRepository struct{ db *sql.DB }

func NewPrivilegeLevelRepository(db *sql.DB) *PrivilegeLevelRepository {
	return &PrivilegeLevelRepository{db: db}
}

func scanPrivilege(row interface{ Scan(...any) error }) (*model.PrivilegeLevel, error) {
	p := &model.PrivilegeLevel{}
	return p, row.Scan(&p.ID, &p.ProjectID, &p.Level, &p.Name, &p.Description)
}

func (r *PrivilegeLevelRepository) FindByProject(projectID int) ([]*model.PrivilegeLevel, error) {
	rows, err := r.db.Query(`SELECT id, project_id, level, name, description FROM project_privilege_levels WHERE project_id = ? ORDER BY level`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var levels []*model.PrivilegeLevel
	for rows.Next() {
		pl, err := scanPrivilege(rows)
		if err != nil {
			return nil, err
		}
		levels = append(levels, pl)
	}
	return levels, nil
}

func (r *PrivilegeLevelRepository) FindByProjectAndLevel(projectID, level int) (*model.PrivilegeLevel, error) {
	row := r.db.QueryRow(`SELECT id, project_id, level, name, description FROM project_privilege_levels WHERE project_id = ? AND level = ?`, projectID, level)
	pl, err := scanPrivilege(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return pl, err
}

func (r *PrivilegeLevelRepository) FindByID(id int) (*model.PrivilegeLevel, error) {
	row := r.db.QueryRow(`SELECT id, project_id, level, name, description FROM project_privilege_levels WHERE id = ?`, id)
	pl, err := scanPrivilege(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return pl, err
}

func (r *PrivilegeLevelRepository) Create(projectID, level int, name, description string) error {
	_, err := r.db.Exec(`INSERT INTO project_privilege_levels (project_id, level, name, description) VALUES (?, ?, ?, ?)`,
		projectID, level, name, description)
	return err
}

func (r *PrivilegeLevelRepository) Update(id int, name, description string) error {
	_, err := r.db.Exec(`UPDATE project_privilege_levels SET name=?, description=? WHERE id=?`, name, description, id)
	return err
}

func (r *PrivilegeLevelRepository) Delete(id int) error {
	_, err := r.db.Exec(`DELETE FROM project_privilege_levels WHERE id=?`, id)
	return err
}
