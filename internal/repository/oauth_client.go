package repository

import (
	"database/sql"
	"encoding/json"

	"blackwall/internal/model"
)

type OAuthClientRepository struct{ db *sql.DB }

func NewOAuthClientRepository(db *sql.DB) *OAuthClientRepository {
	return &OAuthClientRepository{db: db}
}

func scanClient(row interface{ Scan(...any) error }) (*model.OAuthClient, error) {
	c := &model.OAuthClient{}
	var redirectURIs, grants, scopes string
	err := row.Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.ProjectID, &c.Name,
		&redirectURIs, &grants, &scopes,
		&c.PKCERequired, &c.AccessTokenType, &c.AccessTokenLifetime, &c.RefreshTokenLifetime,
		&c.OIDCEnabled, &c.Status, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs)
	json.Unmarshal([]byte(grants), &c.Grants)
	json.Unmarshal([]byte(scopes), &c.Scopes)
	return c, nil
}

const clientSelect = `SELECT id, client_id, client_secret_hash, project_id, name,
	redirect_uris, grants, scopes, pkce_required, access_token_type,
	access_token_lifetime, refresh_token_lifetime, oidc_enabled, status, created_at, updated_at
	FROM oauth_clients`

func (r *OAuthClientRepository) FindByClientID(clientID string) (*model.OAuthClient, error) {
	row := r.db.QueryRow(clientSelect+` WHERE client_id = ?`, clientID)
	c, err := scanClient(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (r *OAuthClientRepository) FindByID(id int) (*model.OAuthClient, error) {
	row := r.db.QueryRow(clientSelect+` WHERE id = ?`, id)
	c, err := scanClient(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (r *OAuthClientRepository) FindAllByProject(projectID int) ([]*model.OAuthClient, error) {
	rows, err := r.db.Query(clientSelect+` WHERE project_id = ? ORDER BY name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []*model.OAuthClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func (r *OAuthClientRepository) Create(clientID, secretHash string, projectID int, name string, redirectURIs, grants, scopes []string, tokenType string, accessLifetime, refreshLifetime int, oidcEnabled bool) (*model.OAuthClient, error) {
	ruJSON, _ := json.Marshal(redirectURIs)
	gJSON, _ := json.Marshal(grants)
	sJSON, _ := json.Marshal(scopes)
	_, err := r.db.Exec(`INSERT INTO oauth_clients
		(client_id, client_secret_hash, project_id, name, redirect_uris, grants, scopes,
		pkce_required, access_token_type, access_token_lifetime, refresh_token_lifetime, oidc_enabled, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'active')`,
		clientID, secretHash, projectID, name, ruJSON, gJSON, sJSON,
		tokenType, accessLifetime, refreshLifetime, oidcEnabled)
	if err != nil {
		return nil, err
	}
	return r.FindByClientID(clientID)
}

func (r *OAuthClientRepository) Update(id int, name string, redirectURIs, grants, scopes []string, tokenType string, accessLifetime, refreshLifetime int, oidcEnabled bool, status string) error {
	ruJSON, _ := json.Marshal(redirectURIs)
	gJSON, _ := json.Marshal(grants)
	sJSON, _ := json.Marshal(scopes)
	_, err := r.db.Exec(`UPDATE oauth_clients SET name=?, redirect_uris=?, grants=?, scopes=?,
		access_token_type=?, access_token_lifetime=?, refresh_token_lifetime=?, oidc_enabled=?, status=?, updated_at=NOW()
		WHERE id=?`,
		name, ruJSON, gJSON, sJSON, tokenType, accessLifetime, refreshLifetime, oidcEnabled, status, id)
	return err
}
