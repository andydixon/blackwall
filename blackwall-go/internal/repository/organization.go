package repository

import (
	"database/sql"

	"blackwall/internal/model"
)

type OrganizationRepository struct{ db *sql.DB }

func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) scan(row interface{ Scan(...any) error }) (*model.Organization, error) {
	o := &model.Organization{}
	err := row.Scan(&o.ID, &o.UUID, &o.Name, &o.Slug, &o.LogoURL, &o.Status, &o.AdminUserID, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

func (r *OrganizationRepository) FindAll() ([]*model.Organization, error) {
	rows, err := r.db.Query(`SELECT id, uuid, name, slug, logo_url, status, admin_user_id, created_at, updated_at FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []*model.Organization
	for rows.Next() {
		o, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, nil
}

func (r *OrganizationRepository) FindByID(id int) (*model.Organization, error) {
	row := r.db.QueryRow(`SELECT id, uuid, name, slug, logo_url, status, admin_user_id, created_at, updated_at FROM organizations WHERE id = ?`, id)
	o, err := r.scan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

func (r *OrganizationRepository) FindByUUID(uuid string) (*model.Organization, error) {
	row := r.db.QueryRow(`SELECT id, uuid, name, slug, logo_url, status, admin_user_id, created_at, updated_at FROM organizations WHERE uuid = ?`, uuid)
	o, err := r.scan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

func (r *OrganizationRepository) FindBySlug(slug string) (*model.Organization, error) {
	row := r.db.QueryRow(`SELECT id, uuid, name, slug, logo_url, status, admin_user_id, created_at, updated_at FROM organizations WHERE slug = ?`, slug)
	o, err := r.scan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

func (r *OrganizationRepository) FindDefault() (*model.Organization, error) {
	return r.FindByUUID("00000000-0000-0000-0000-000000000001")
}

func (r *OrganizationRepository) Create(uuid, name, slug string) (*model.Organization, error) {
	_, err := r.db.Exec(`INSERT INTO organizations (uuid, name, slug, status) VALUES (?, ?, ?, 'active')`, uuid, name, slug)
	if err != nil {
		return nil, err
	}
	return r.FindByUUID(uuid)
}

func (r *OrganizationRepository) Update(id int, name, slug, status string, logoURL sql.NullString) error {
	_, err := r.db.Exec(`UPDATE organizations SET name=?, slug=?, status=?, logo_url=?, updated_at=NOW() WHERE id=?`,
		name, slug, status, logoURL, id)
	return err
}

func (r *OrganizationRepository) SetAdminUser(orgID, userID int) error {
	_, err := r.db.Exec(`UPDATE organizations SET admin_user_id=?, updated_at=NOW() WHERE id=?`, userID, orgID)
	return err
}
