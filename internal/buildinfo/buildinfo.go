package buildinfo

import "strings"

var (
	VersionTag  = "dev"
	CommitShort = "unknown"
	BuildDate   = "unknown"
)

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
