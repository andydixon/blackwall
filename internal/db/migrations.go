package db

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// isMySQLDupColumnErr returns true when an ALTER TABLE ADD COLUMN failed
// because the column already exists. MySQL surfaces error 1060 with a stable
// "Duplicate column name" message; we string-match so we can re-run a partial
// migration without crashing.
func isMySQLDupColumnErr(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "duplicate column name") || strings.Contains(m, "error 1060")
}

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
	{
		Version: 3,
		Description: "Enterprise-tier scaffolding: project feature flags, webhook endpoints + deliveries, " +
			"DB-backed user sessions, organisation branding, custom domains, audit chain checkpoints, " +
			"and admin API tokens",
		Apply: func(db *sql.DB) error {
			// Per-project feature flag table — controls which enterprise
			// features apply to which project. New rows for new projects are
			// created with enterprise features on; existing projects (rows
			// already in `projects`) get a backfill row with them OFF, so
			// production behaviour is unchanged on upgrade.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS project_features (
				project_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
				webhooks_enabled TINYINT(1) NOT NULL DEFAULT 0,
				db_sessions_enabled TINYINT(1) NOT NULL DEFAULT 0,
				max_concurrent_sessions INT NOT NULL DEFAULT 0,
				custom_branding_enabled TINYINT(1) NOT NULL DEFAULT 0,
				step_up_required TINYINT(1) NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}
			// Backfill: every existing project gets a feature row with the
			// new toggles OFF, preserving current behaviour. The handler that
			// CREATES new projects from now on will insert a row with the
			// new toggles ON by default (see ProjectStore).
			if _, err := db.Exec(`INSERT IGNORE INTO project_features (project_id) SELECT id FROM projects`); err != nil {
				return err
			}

			// Outbound webhook endpoints — one row per (project, target URL).
			// Secret is used for the HMAC-SHA256 X-BlackWall-Signature header.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS webhook_endpoints (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				project_id BIGINT UNSIGNED NOT NULL,
				public_id CHAR(36) NOT NULL UNIQUE,
				target_url VARCHAR(2048) NOT NULL,
				secret VARCHAR(128) NOT NULL,
				events_json TEXT NOT NULL,
				status ENUM('active','disabled') NOT NULL DEFAULT 'active',
				description VARCHAR(255) DEFAULT NULL,
				last_success_at DATETIME DEFAULT NULL,
				last_failure_at DATETIME DEFAULT NULL,
				consecutive_failures INT NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				INDEX idx_we_project (project_id, status)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// Per-attempt delivery record. We keep these for debuggability +
			// "resend" support from the admin UI; the cleanup job trims them.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS webhook_deliveries (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				endpoint_id BIGINT UNSIGNED NOT NULL,
				event_type VARCHAR(80) NOT NULL,
				event_id CHAR(36) NOT NULL,
				payload_json MEDIUMTEXT NOT NULL,
				status ENUM('pending','succeeded','failed','exhausted') NOT NULL DEFAULT 'pending',
				attempts INT NOT NULL DEFAULT 0,
				last_status_code INT DEFAULT NULL,
				last_response_excerpt TEXT DEFAULT NULL,
				next_attempt_at DATETIME NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
				INDEX idx_wd_pending (status, next_attempt_at),
				INDEX idx_wd_event (event_id)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// DB-backed session metadata. The actual session payload still
			// lives in the encrypted cookie; this row exists so the server
			// can list a user's active sessions and force-revoke any one.
			// The cookie carries the session_id; if no matching active row
			// exists, the session is rejected.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_sessions (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				session_id CHAR(43) NOT NULL UNIQUE,
				user_id BIGINT UNSIGNED NOT NULL,
				scope ENUM('admin','portal') NOT NULL,
				ip_address VARCHAR(45) DEFAULT NULL,
				user_agent VARCHAR(512) DEFAULT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME NOT NULL,
				revoked_at DATETIME DEFAULT NULL,
				revoked_reason VARCHAR(100) DEFAULT NULL,
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
				INDEX idx_us_user_active (user_id, revoked_at, expires_at),
				INDEX idx_us_expiry (expires_at, revoked_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// Per-organisation branding. NULLABLE columns so existing orgs
			// pick up the default UI without any change to their rows.
			if _, err := db.Exec(`ALTER TABLE organizations
				ADD COLUMN logo_url VARCHAR(1024) DEFAULT NULL,
				ADD COLUMN primary_color VARCHAR(16) DEFAULT NULL,
				ADD COLUMN login_message VARCHAR(2048) DEFAULT NULL,
				ADD COLUMN support_email VARCHAR(255) DEFAULT NULL`); err != nil {
				// MySQL doesn't have "ADD COLUMN IF NOT EXISTS" — if any of
				// these already exist (re-run on a partially-applied env)
				// we just continue. The schema_migrations gate prevents
				// double-application on healthy systems.
				if !isMySQLDupColumnErr(err) {
					return err
				}
			}

			// Custom domain → organisation routing. Host matched
			// case-insensitively; SSL cert provisioning is operator's job.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS org_custom_domains (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				organization_id BIGINT UNSIGNED NOT NULL,
				hostname VARCHAR(253) NOT NULL UNIQUE,
				verified TINYINT(1) NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// Audit chain checkpoints — periodic signed snapshots of
			// (last_id, last_chain_hash) so an external observer can verify
			// no rows were silently rewritten between checkpoints.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				last_audit_id BIGINT UNSIGNED NOT NULL,
				last_chain_hash CHAR(64) NOT NULL,
				row_count BIGINT UNSIGNED NOT NULL,
				signature TEXT NOT NULL,
				signing_key_id VARCHAR(64) NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				exported_to VARCHAR(255) DEFAULT NULL,
				INDEX idx_ckpt_created (created_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// Admin API bearer tokens. Token plaintext is shown ONCE at
			// creation; we store only a SHA-256 hash plus a short prefix for
			// UI identification ("bw_admin_*"). Each token is bound to a
			// user, inherits that user's admin capabilities at request time
			// (no token-side cap escalation possible).
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS admin_api_tokens (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				public_id CHAR(36) NOT NULL UNIQUE,
				prefix VARCHAR(16) NOT NULL,
				token_hash CHAR(64) NOT NULL UNIQUE,
				user_id BIGINT UNSIGNED NOT NULL,
				name VARCHAR(255) NOT NULL,
				scopes_json TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				last_used_at DATETIME DEFAULT NULL,
				expires_at DATETIME DEFAULT NULL,
				revoked_at DATETIME DEFAULT NULL,
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
				INDEX idx_aat_user (user_id, revoked_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			return nil
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
