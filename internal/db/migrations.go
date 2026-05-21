package db

import (
	"database/sql"
	"fmt"
	"log"
)

// migration is a single forward-only schema change applied idempotently at
// boot. The Apply function MUST be safe to re-run if a previous attempt
// failed partway through (use IF NOT EXISTS / IF EXISTS guards).
//
// We track applied versions in `schema_migrations` to skip work on subsequent
// startups. The base schema is assumed to already exist (BlackWall ships a
// pre-existing MySQL schema).
type migration struct {
	Version     int
	Description string
	Apply       func(db *sql.DB) error
}

// migrations is the ordered list of forward-only schema upgrades the binary
// knows how to apply on top of the base schema. Add new entries at the END;
// never reorder, never edit history.
var migrations = []migration{
	{
		Version:     1,
		Description: "Custom OIDC claims (per-user and per-user-per-project key/value)",
		Apply: func(db *sql.DB) error {
			// User-level claims: set on a user, returned in every ID token /
			// userinfo for that user regardless of project.
			//
			// claim_key uses VARCHAR(80) to accommodate any sensible OIDC
			// claim name and is part of the unique key so each user holds at
			// most one value per key.
			_, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_oidc_claims (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				user_id BIGINT UNSIGNED NOT NULL,
				claim_key VARCHAR(80) NOT NULL,
				claim_value TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				UNIQUE KEY uk_user_claim (user_id, claim_key),
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
				INDEX idx_user_claim_key (user_id, claim_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			if err != nil {
				return err
			}
			// Project-scoped claims: only included when the issued token is
			// bound to that project (i.e. the request reached our server with
			// the matching project context).
			_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_project_oidc_claims (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				user_id BIGINT UNSIGNED NOT NULL,
				project_id BIGINT UNSIGNED NOT NULL,
				claim_key VARCHAR(80) NOT NULL,
				claim_value TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				UNIQUE KEY uk_user_project_claim (user_id, project_id, claim_key),
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				INDEX idx_upc (user_id, project_id, claim_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			return err
		},
	},
	{
		Version:     2,
		Description: "Default OIDC claims at organisation and project level (templates merged into every user)",
		Apply: func(db *sql.DB) error {
			// Organisation-level default claims: form the lowest precedence
			// layer, applied to every token issued for a user in this org
			// regardless of project. Per-user values still override.
			_, err := db.Exec(`CREATE TABLE IF NOT EXISTS organization_oidc_claim_defaults (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				organization_id BIGINT UNSIGNED NOT NULL,
				claim_key VARCHAR(80) NOT NULL,
				claim_value TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				UNIQUE KEY uk_org_claim_default (organization_id, claim_key),
				FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
				INDEX idx_org_claim_default (organization_id, claim_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			if err != nil {
				return err
			}
			// Project-level default claims: overlay org defaults whenever a
			// token is bound to this project. Per-user values still override
			// these in turn (narrowest layer wins).
			_, err = db.Exec(`CREATE TABLE IF NOT EXISTS project_oidc_claim_defaults (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				project_id BIGINT UNSIGNED NOT NULL,
				claim_key VARCHAR(80) NOT NULL,
				claim_value TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				UNIQUE KEY uk_project_claim_default (project_id, claim_key),
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				INDEX idx_project_claim_default (project_id, claim_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			return err
		},
	},
}

// Migrate applies every pending migration in order under a single tracking
// table. Safe to call on every startup — already-applied versions are skipped.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INT UNSIGNED PRIMARY KEY,
		description VARCHAR(255) NOT NULL,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		var existing int
		if err := db.QueryRow(`SELECT 1 FROM schema_migrations WHERE version=?`, m.Version).Scan(&existing); err == nil && existing == 1 {
			continue
		}

		log.Printf("[migrate] applying %d: %s", m.Version, m.Description)
		if err := m.Apply(db); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.Version, m.Description, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version, description) VALUES (?, ?)`, m.Version, m.Description); err != nil {
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}
	}
	return nil
}
