package service

import (
	"database/sql"
	"errors"
)

// ProjectFeatures captures the per-project enterprise-tier toggles. A row in
// `project_features` mirrors this struct one-to-one. New projects are created
// with the modern defaults (webhooks + DB sessions + custom branding on);
// existing projects keep the migration's "all-off" backfill so upgrading
// BlackWall doesn't change the behaviour of in-flight deployments.
//
// The fields are deliberately granular rather than a single tier enum: each
// feature represents work that may or may not be wired in for a given project,
// and admins frequently want to enable just one (e.g. webhooks without
// touching the session-management surface).
type ProjectFeatures struct {
	ProjectID             int
	WebhooksEnabled       bool
	DBSessionsEnabled     bool
	MaxConcurrentSessions int
	CustomBrandingEnabled bool
	StepUpRequired        bool
}

// DefaultProjectFeatures returns the toggles applied to NEWLY created
// projects. We turn webhooks, DB-backed sessions, and custom branding on by
// default so new tenants get the polished experience without an opt-in step;
// step-up auth stays off because it changes the login UX and should be a
// deliberate choice. MaxConcurrentSessions=0 means "no cap" — preserves the
// historic behaviour even for new projects.
func DefaultProjectFeatures() ProjectFeatures {
	return ProjectFeatures{
		WebhooksEnabled:       true,
		DBSessionsEnabled:     true,
		MaxConcurrentSessions: 0,
		CustomBrandingEnabled: true,
		StepUpRequired:        false,
	}
}

// FeatureFlagService is the single owner of the project_features table. All
// reads and writes funnel through here so a future move to a cached or
// distributed flag store stays a one-package change.
type FeatureFlagService struct {
	db *sql.DB
}

func NewFeatureFlagService(db *sql.DB) *FeatureFlagService {
	return &FeatureFlagService{db: db}
}

// Get returns the per-project toggle set. If no row exists (i.e. the project
// was created before migration v3 and the backfill somehow missed it) we
// return the legacy-safe all-OFF defaults rather than an error — production
// behaviour for that project should not change unexpectedly.
func (s *FeatureFlagService) Get(projectID int) (ProjectFeatures, error) {
	if projectID <= 0 {
		return ProjectFeatures{}, errors.New("project_id must be positive")
	}
	f := ProjectFeatures{ProjectID: projectID}
	err := s.db.QueryRow(`SELECT webhooks_enabled, db_sessions_enabled, max_concurrent_sessions,
		custom_branding_enabled, step_up_required
		FROM project_features WHERE project_id=?`, projectID).Scan(
		&f.WebhooksEnabled, &f.DBSessionsEnabled, &f.MaxConcurrentSessions,
		&f.CustomBrandingEnabled, &f.StepUpRequired)
	if err == sql.ErrNoRows {
		return ProjectFeatures{ProjectID: projectID}, nil
	}
	return f, err
}

// EnsureForNewProject inserts a row carrying DefaultProjectFeatures for a
// project that was just created. Safe to call on an already-present row —
// the INSERT IGNORE pattern silently no-ops in that case so we don't clobber
// an admin's manual override.
func (s *FeatureFlagService) EnsureForNewProject(projectID int) error {
	d := DefaultProjectFeatures()
	_, err := s.db.Exec(`INSERT IGNORE INTO project_features
		(project_id, webhooks_enabled, db_sessions_enabled, max_concurrent_sessions, custom_branding_enabled, step_up_required)
		VALUES (?, ?, ?, ?, ?, ?)`,
		projectID, d.WebhooksEnabled, d.DBSessionsEnabled, d.MaxConcurrentSessions,
		d.CustomBrandingEnabled, d.StepUpRequired)
	return err
}

// Update writes the full feature set for the project. Upserts so callers
// don't need to distinguish "no row" from "existing row" — both end with the
// supplied values stored.
func (s *FeatureFlagService) Update(projectID int, f ProjectFeatures) error {
	if projectID <= 0 {
		return errors.New("project_id must be positive")
	}
	if f.MaxConcurrentSessions < 0 {
		return errors.New("max_concurrent_sessions must be non-negative")
	}
	_, err := s.db.Exec(`INSERT INTO project_features
		(project_id, webhooks_enabled, db_sessions_enabled, max_concurrent_sessions, custom_branding_enabled, step_up_required)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			webhooks_enabled=VALUES(webhooks_enabled),
			db_sessions_enabled=VALUES(db_sessions_enabled),
			max_concurrent_sessions=VALUES(max_concurrent_sessions),
			custom_branding_enabled=VALUES(custom_branding_enabled),
			step_up_required=VALUES(step_up_required)`,
		projectID, f.WebhooksEnabled, f.DBSessionsEnabled, f.MaxConcurrentSessions,
		f.CustomBrandingEnabled, f.StepUpRequired)
	return err
}
