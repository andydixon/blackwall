package db

import (
	"database/sql"
	_ "embed"
	"fmt"
	"log"
)

// schemaSQL is the complete PostgreSQL schema: every table, index, constraint,
// and helper function BlackWall needs. It is generated from the schema MariaDB
// carried at the point of the PostgreSQL migration, which is to say it already
// includes the effect of historical migrations 1 through 7.
//
// It is maintained by hand: a schema change must be added both to schema.sql
// (for fresh installs) and as a numbered migration below (for existing
// databases), so the two paths converge on the same shape.
//
//go:embed schema.sql
var schemaSQL string

// baselineVersion is the highest migration version folded into schema.sql. A
// database created from that file is recorded as having applied every version
// up to and including this one.
const baselineVersion = 7

// baselineDescriptions records what each folded-in version did, so
// schema_migrations reads the same on a freshly created database as it does on
// one carried over from MariaDB.
var baselineDescriptions = map[int]string{
	1: "Custom OIDC claims (per-user and per-user-per-project key/value)",
	2: "Default OIDC claims at organisation and project level (templates merged into every user)",
	3: "Enterprise-tier scaffolding: project feature flags, webhook endpoints + deliveries, " +
		"DB-backed user sessions, organisation branding, custom domains, audit chain checkpoints, " +
		"and admin API tokens",
	4: "SAML 2.0 service providers (per-project SP registry) and SCIM external_id mapping " +
		"for round-tripping HRIS-driven provisioning.",
	5: "Persist OIDC authentication time on authorization codes and refresh tokens",
	6: "Ed25519-signed, hostname-bound project licences and signing-key registry",
	7: "Durable, duplicate-safe project licence renewal reminders",
}

// migration is a single forward-only schema change applied idempotently at
// boot. The Apply function MUST be safe to re-run if a previous attempt failed
// partway through — PostgreSQL supports IF NOT EXISTS on CREATE TABLE, CREATE
// INDEX, and ALTER TABLE ... ADD COLUMN, so use those guards.
//
// Applied versions are tracked in schema_migrations so later startups skip the
// work.
type migration struct {
	Version     int
	Description string
	Apply       func(db *sql.DB) error
}

// migrations is the ordered list of forward-only schema upgrades applied on top
// of the baseline in schema.sql. Add new entries at the END with versions above
// baselineVersion; never reorder, never edit history.
//
// Versions 1 to 7 are deliberately absent: they were MySQL DDL that cannot run
// against PostgreSQL, they are already folded into schema.sql, and every live
// database records them as applied.
var migrations = []migration{
	{
		Version:     8,
		Description: "Restore the organisation branding columns migration 3 failed to add",
		Apply: func(db *sql.DB) error {
			// Migration 3 added logo_url, primary_color, login_message and
			// support_email in a single multi-column ALTER. logo_url already
			// existed, so MySQL rejected the whole statement as a duplicate
			// column — and the error was swallowed as "already applied",
			// leaving the other three columns absent while the migration was
			// recorded as complete. Branding has been broken ever since.
			//
			// PostgreSQL applies ADD COLUMN IF NOT EXISTS per column, so this
			// class of partial failure cannot recur here.
			_, err := db.Exec(`ALTER TABLE organizations
				ADD COLUMN IF NOT EXISTS primary_color VARCHAR(16),
				ADD COLUMN IF NOT EXISTS login_message VARCHAR(2048),
				ADD COLUMN IF NOT EXISTS support_email VARCHAR(255)`)
			return err
		},
	},
}

// Migrate brings the database up to date: it installs the baseline schema on an
// empty database, then applies any pending migrations in order. Safe to call on
// every startup.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		description VARCHAR(255) NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	if err := applyBaseline(db); err != nil {
		return err
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

// applyBaseline installs schema.sql when the database has no application tables
// yet. An existing database — including one carried across from MariaDB — is
// left completely alone.
func applyBaseline(db *sql.DB) error {
	var present bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.tables
		WHERE table_schema='public' AND table_name='users')`).Scan(&present); err != nil {
		return fmt.Errorf("probe for baseline schema: %w", err)
	}
	if present {
		return nil
	}

	log.Print("[migrate] empty database — installing baseline schema")
	if _, err := db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("install baseline schema: %w", err)
	}
	for v := 1; v <= baselineVersion; v++ {
		if _, err := db.Exec(
			`INSERT INTO schema_migrations (version, description) VALUES (?, ?)
			 ON CONFLICT (version) DO NOTHING`,
			v, baselineDescriptions[v]); err != nil {
			return fmt.Errorf("record baseline version %d: %w", v, err)
		}
	}
	log.Printf("[migrate] baseline installed (versions 1-%d)", baselineVersion)
	return nil
}
