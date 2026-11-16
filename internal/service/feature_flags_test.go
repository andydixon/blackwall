// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package service

import "testing"

// TestDefaultProjectFeatures pins the "new projects get enterprise on" stance.
// If this test ever flips, the user-facing promise the migration relies on
// has changed — make sure that's intentional and document the upgrade story.
func TestDefaultProjectFeatures(t *testing.T) {
	d := DefaultProjectFeatures()
	if !d.WebhooksEnabled {
		t.Errorf("default should enable webhooks for new projects")
	}
	if !d.DBSessionsEnabled {
		t.Errorf("default should enable DB-backed sessions for new projects")
	}
	if !d.CustomBrandingEnabled {
		t.Errorf("default should enable custom branding for new projects")
	}
	if d.StepUpRequired {
		t.Errorf("step-up should be off by default — it changes login UX")
	}
	if d.MaxConcurrentSessions != 0 {
		t.Errorf("max concurrent sessions should be unbounded by default")
	}
}
