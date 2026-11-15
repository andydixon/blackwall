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
	{
		Version: 4,
		Description: "SAML 2.0 service providers (per-project SP registry) and SCIM external_id mapping " +
			"for round-tripping HRIS-driven provisioning.",
		Apply: func(db *sql.DB) error {
			// SAML SP registration — one row per (project, entity_id). Stores
			// the SP's ACS URL and the certificate we'll use to verify any
			// signed AuthnRequests. attribute_map_json captures which user
			// fields go into which SAML attribute statements so the SP gets
			// what it expects without us hard-coding "email" everywhere.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS saml_service_providers (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				public_id CHAR(36) NOT NULL UNIQUE,
				project_id BIGINT UNSIGNED NOT NULL,
				entity_id VARCHAR(1024) NOT NULL,
				acs_url VARCHAR(2048) NOT NULL,
				slo_url VARCHAR(2048) DEFAULT NULL,
				name_id_format VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
				sign_assertions TINYINT(1) NOT NULL DEFAULT 1,
				sign_response TINYINT(1) NOT NULL DEFAULT 1,
				sp_cert_pem TEXT DEFAULT NULL,
				attribute_map_json TEXT NOT NULL,
				audience VARCHAR(1024) DEFAULT NULL,
				status ENUM('active','disabled') NOT NULL DEFAULT 'active',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				UNIQUE KEY uk_saml_sp_entity (project_id, entity_id),
				INDEX idx_saml_sp_project (project_id, status)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// SCIM external_id mapping — when an upstream HRIS provisions a
			// user it generates its own ID; we store it so subsequent PUTs /
			// PATCHes / DELETEs from the same HRIS can find the row. Keyed
			// per project so two HRIS systems can both push the same email
			// without colliding.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS scim_user_mapping (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				project_id BIGINT UNSIGNED NOT NULL,
				user_id BIGINT UNSIGNED NOT NULL,
				external_id VARCHAR(255) NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				UNIQUE KEY uk_scim_external (project_id, external_id),
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
				INDEX idx_scim_user (user_id, project_id)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			return nil
		},
	},
	{
		Version:     5,
		Description: "Persist OIDC authentication time on authorization codes and refresh tokens",
		Apply: func(db *sql.DB) error {
			statements := []string{
				`ALTER TABLE oauth_auth_codes ADD COLUMN auth_time BIGINT UNSIGNED DEFAULT NULL AFTER nonce`,
				`ALTER TABLE oauth_refresh_tokens ADD COLUMN auth_time BIGINT UNSIGNED DEFAULT NULL AFTER privilege_level`,
			}
			for _, statement := range statements {
				if _, err := db.Exec(statement); err != nil && !isMySQLDupColumnErr(err) {
					return err
				}
			}
			return nil
		},
	},
	{
		Version:     6,
		Description: "Ed25519-signed, hostname-bound project licences and signing-key registry",
		Apply: func(db *sql.DB) error {
			// Only public key material is persisted. The active private key is
			// supplied through a permission-restricted file and never enters the
			// database, backups, admin UI, audit log, or licence-verification API.
			if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS licence_signing_keys (
				kid VARCHAR(64) NOT NULL PRIMARY KEY,
				algorithm VARCHAR(16) NOT NULL,
				public_key_base64 VARCHAR(128) NOT NULL,
				status ENUM('active','retired','compromised') NOT NULL DEFAULT 'active',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				retired_at DATETIME DEFAULT NULL,
				UNIQUE KEY uk_licence_public_key (public_key_base64)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
				return err
			}

			// The signed payload and signature are retained byte-for-byte. Online
			// verification requires both a valid signature and a matching database
			// record, so possession of a copied token cannot bypass revocation and
			// possession of a signing key alone cannot invent an online-valid row.
			_, err := db.Exec(`CREATE TABLE IF NOT EXISTS project_licences (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				public_id CHAR(36) NOT NULL UNIQUE,
				project_id BIGINT UNSIGNED NOT NULL,
				entity_type ENUM('person','business') NOT NULL,
				entity_name VARCHAR(255) NOT NULL,
				entity_reference VARCHAR(255) DEFAULT NULL,
				hostnames_json TEXT NOT NULL,
				features_json TEXT NOT NULL,
				max_instances INT UNSIGNED NOT NULL DEFAULT 1,
				not_before DATETIME NOT NULL,
				expires_at DATETIME NOT NULL,
				issued_at DATETIME NOT NULL,
				issued_by_user_id BIGINT UNSIGNED DEFAULT NULL,
				revoked_at DATETIME DEFAULT NULL,
				revoked_by_user_id BIGINT UNSIGNED DEFAULT NULL,
				revocation_reason VARCHAR(500) DEFAULT NULL,
				signing_key_id VARCHAR(64) NOT NULL,
				payload_json TEXT NOT NULL,
				signature_base64 VARCHAR(128) NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
				FOREIGN KEY (issued_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
				FOREIGN KEY (revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
				FOREIGN KEY (signing_key_id) REFERENCES licence_signing_keys(kid),
				INDEX idx_licence_project_status (project_id, revoked_at, expires_at),
				INDEX idx_licence_key (signing_key_id)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			return err
		},
	},
	{
		Version:     7,
		Description: "Durable, duplicate-safe project licence renewal reminders",
		Apply: func(db *sql.DB) error {
			// One row represents one recipient at one countdown threshold. The
			// uniqueness constraint is the last line of defence against duplicate
			// mail when several Blackwall instances scan at the same time.
			_, err := db.Exec(`CREATE TABLE IF NOT EXISTS licence_renewal_reminders (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				licence_id BIGINT UNSIGNED NOT NULL,
				threshold_days TINYINT UNSIGNED NOT NULL,
				recipient_user_id BIGINT UNSIGNED NOT NULL,
				recipient_email VARCHAR(254) NOT NULL,
				status ENUM('pending','sending','succeeded','exhausted','cancelled') NOT NULL DEFAULT 'pending',
				attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
				next_attempt_at DATETIME NOT NULL,
				locked_at DATETIME DEFAULT NULL,
				lock_token CHAR(36) DEFAULT NULL,
				last_error_code VARCHAR(64) DEFAULT NULL,
				sent_at DATETIME DEFAULT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				FOREIGN KEY (licence_id) REFERENCES project_licences(id) ON DELETE CASCADE,
				FOREIGN KEY (recipient_user_id) REFERENCES users(id),
				UNIQUE KEY uk_licence_reminder_recipient (licence_id, threshold_days, recipient_user_id),
				INDEX idx_licence_reminder_queue (status, next_attempt_at),
				INDEX idx_licence_reminder_project (licence_id, created_at),
				CONSTRAINT chk_licence_reminder_threshold CHECK (threshold_days IN (30,14,7,2,1))
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
			return err
		},
	},
	{
		Version:     8,
		Description: "Restore the organisation branding columns migration 3 failed to add",
		Apply: func(db *sql.DB) error {
			// Migration 3 added logo_url, primary_color, login_message and
			// support_email in a single multi-column ALTER. logo_url already
			// existed, so MySQL rejected the whole statement as a duplicate
			// column — and the error was swallowed as "already applied",
			// leaving the other three columns absent. One column per ALTER
			// means a duplicate can only ever skip the column it names.
			for _, statement := range []string{
				`ALTER TABLE organizations ADD COLUMN primary_color VARCHAR(16) NULL`,
				`ALTER TABLE organizations ADD COLUMN login_message VARCHAR(2048) NULL`,
				`ALTER TABLE organizations ADD COLUMN support_email VARCHAR(255) NULL`,
			} {
				if _, err := db.Exec(statement); err != nil && !isMySQLDupColumnErr(err) {
					return err
				}
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
