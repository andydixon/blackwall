package repository

import (
	"database/sql"

	"blackwall/internal/model"
)

type ProjectRepository struct{ db *sql.DB }

func NewProjectRepository(db *sql.DB) *ProjectRepository {
	return &ProjectRepository{db: db}
}

const projectSelect = `SELECT id, organization_id, uuid, name, owner_user_id, status, created_at, updated_at FROM projects`

func scanProject(row interface{ Scan(...any) error }) (*model.Project, error) {
	p := &model.Project{}
	err := row.Scan(&p.ID, &p.OrganizationID, &p.UUID, &p.Name, &p.OwnerUserID, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func (r *ProjectRepository) FindByID(id int) (*model.Project, error) {
	row := r.db.QueryRow(projectSelect+` WHERE id = ?`, id)
	p, err := scanProject(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (r *ProjectRepository) FindByUUID(uuid string) (*model.Project, error) {
	row := r.db.QueryRow(projectSelect+` WHERE uuid = ?`, uuid)
	p, err := scanProject(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (r *ProjectRepository) FindByName(name string) (*model.Project, error) {
	row := r.db.QueryRow(projectSelect+` WHERE name = ?`, name)
	p, err := scanProject(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (r *ProjectRepository) FindAll() ([]*model.Project, error) {
	rows, err := r.db.Query(projectSelect + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProjects(rows)
}

func (r *ProjectRepository) FindByOrganization(orgID int) ([]*model.Project, error) {
	rows, err := r.db.Query(projectSelect+` WHERE organization_id = ? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProjects(rows)
}

func scanProjects(rows *sql.Rows) ([]*model.Project, error) {
	var projects []*model.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

func (r *ProjectRepository) Create(orgID int, uuid, name string, ownerUserID sql.NullInt64) (*model.Project, error) {
	_, err := r.db.Exec(`INSERT INTO projects (organization_id, uuid, name, owner_user_id, status) VALUES (?, ?, ?, ?, 'active')`,
		orgID, uuid, name, ownerUserID)
	if err != nil {
		return nil, err
	}
	return r.FindByUUID(uuid)
}

func (r *ProjectRepository) Update(id int, name, status string) error {
	_, err := r.db.Exec(`UPDATE projects SET name=?, status=?, updated_at=NOW() WHERE id=?`, name, status, id)
	return err
}
