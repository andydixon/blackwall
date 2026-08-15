// Package buildinfo exposes deliberately limited provenance data embedded by
// the release pipeline. It must never grow to include module versions or other
// dependency inventory: the values are rendered to authenticated administrators.
package buildinfo

import (
	"strings"
	"time"
)

var (
	VersionTag  = "dev"
	CommitShort = "unknown"
	BuildDate   = "unknown"

	// VulnerabilityScanDate and VulnerabilityScanReference describe the most
	// recent successful scan accepted by the build pipeline. Findings and
	// package names remain in the private scanner output and are never embedded.
	VulnerabilityScanDate      = "unknown"
	VulnerabilityScanReference = "unknown"
)

// Status is the non-sensitive release provenance shown in the admin panel.
type Status struct {
	Version                    string
	Commit                     string
	BuildTime                  string
	VulnerabilityScanRecorded  bool
	VulnerabilityScanTime      string
	VulnerabilityScanReference string
}

func DisplayVersion() string {
	tag := strings.TrimSpace(VersionTag)
	commit := strings.TrimSpace(CommitShort)

	if tag == "" {
		tag = "dev"
	}
	if commit == "" {
		commit = "unknown"
	}

	return tag + "-" + commit
}

// Current returns normalised, display-safe build provenance. A vulnerability
// scan is treated as recorded only when its completion time is valid RFC 3339
// and its opaque pipeline reference is present. This prevents a partial build
// configuration from being presented as a successful security check.
func Current() Status {
	status := Status{
		Version:   cleanValue(VersionTag, "dev", 128),
		Commit:    cleanValue(CommitShort, "unknown", 64),
		BuildTime: normaliseTime(BuildDate),
	}

	scanTime := normaliseTime(VulnerabilityScanDate)
	scanReference := cleanValue(VulnerabilityScanReference, "unknown", 160)
	if scanTime != "unknown" && scanReference != "unknown" {
		status.VulnerabilityScanRecorded = true
		status.VulnerabilityScanTime = scanTime
		status.VulnerabilityScanReference = scanReference
	} else {
		status.VulnerabilityScanTime = "Not supplied"
		status.VulnerabilityScanReference = "Not supplied"
	}
	return status
}

func normaliseTime(raw string) string {
	value := strings.TrimSpace(raw)
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "unknown"
	}
	return parsed.UTC().Format(time.RFC3339)
}

func cleanValue(raw, fallback string, maximum int) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return fallback
	}
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}
