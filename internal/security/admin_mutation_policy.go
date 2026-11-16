// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package security

import (
	"sort"
	"strings"
)

// ProjectSettings is the canonical view of project fields that participate
// in the approval-vs-direct decision (currently name + status).
type ProjectSettings struct {
	Name   string
	Status string
}

// ClientSettings captures every OAuth-client field that, if changed, would
// require an approval when the actor lacks the *_direct capability.
type ClientSettings struct {
	Name                 string
	Status               string
	RedirectURIs         []string
	Scopes               []string
	AccessTokenType      string
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	OIDCEnabled          bool
}

// ShouldRequireProjectSettingsApproval returns true if the actor cannot apply
// the change directly AND the request actually changes a tracked field.
func ShouldRequireProjectSettingsApproval(canApplyDirectly bool, current, requested ProjectSettings) bool {
	if canApplyDirectly {
		return false
	}
	return strings.TrimSpace(current.Name) != strings.TrimSpace(requested.Name) ||
		current.Status != requested.Status
}

// ShouldRequireClientSettingsApproval returns true if the actor cannot apply
// the change directly AND the normalised settings differ.
func ShouldRequireClientSettingsApproval(canApplyDirectly bool, current, requested ClientSettings) bool {
	if canApplyDirectly {
		return false
	}
	return !clientSettingsEqual(current, requested)
}

// ShouldRequireAssignmentApproval matches PHP: assignment mutations always
// require approval unless the role has the *_direct capability.
func ShouldRequireAssignmentApproval(canApplyDirectly bool) bool {
	return !canApplyDirectly
}

func clientSettingsEqual(a, b ClientSettings) bool {
	if strings.TrimSpace(a.Name) != strings.TrimSpace(b.Name) {
		return false
	}
	if a.Status != b.Status {
		return false
	}
	if a.AccessTokenType != b.AccessTokenType {
		return false
	}
	if a.AccessTokenLifetime != b.AccessTokenLifetime {
		return false
	}
	if a.RefreshTokenLifetime != b.RefreshTokenLifetime {
		return false
	}
	if a.OIDCEnabled != b.OIDCEnabled {
		return false
	}
	if !sortedEqual(a.RedirectURIs, b.RedirectURIs) {
		return false
	}
	if !sortedEqual(a.Scopes, b.Scopes) {
		return false
	}
	return true
}

func sortedEqual(a, b []string) bool {
	an := normaliseStrings(a)
	bn := normaliseStrings(b)
	if len(an) != len(bn) {
		return false
	}
	for i := range an {
		if an[i] != bn[i] {
			return false
		}
	}
	return true
}

func normaliseStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		t := strings.TrimSpace(v)
		if t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
