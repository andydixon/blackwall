package buildinfo

import "testing"

func TestCurrentRequiresCompleteScanMetadata(t *testing.T) {
	originalDate, originalReference := VulnerabilityScanDate, VulnerabilityScanReference
	t.Cleanup(func() {
		VulnerabilityScanDate = originalDate
		VulnerabilityScanReference = originalReference
	})

	VulnerabilityScanDate = "2026-08-15T12:30:00Z"
	VulnerabilityScanReference = "ci/security/1842"
	got := Current()
	if !got.VulnerabilityScanRecorded {
		t.Fatal("expected complete vulnerability scan metadata to be recorded")
	}
	if got.VulnerabilityScanTime != "2026-08-15T12:30:00Z" {
		t.Fatalf("unexpected normalised scan time: %q", got.VulnerabilityScanTime)
	}

	VulnerabilityScanDate = "not-a-date"
	got = Current()
	if got.VulnerabilityScanRecorded {
		t.Fatal("invalid scan time must not be presented as a successful scan")
	}
}

func TestCurrentRemovesControlCharacters(t *testing.T) {
	originalTag := VersionTag
	t.Cleanup(func() { VersionTag = originalTag })
	VersionTag = "release\nforged"
	if got := Current().Version; got != "releaseforged" {
		t.Fatalf("control character was not removed: %q", got)
	}
}
