// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version

import (
	"context"
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// version a string since it is overwritten at build-time with the git tag for official releases.
var version = "v1.6-rc"

// Version is the branch version of the codebase.
//   - Main branch: v0.X-dev
//   - Release branch: v0.Y-rc
var Version, _ = Parse(version) // Error is caught in tests.

// Supported returns the supported minor versions in order of precedence.
func Supported() []SemVer {
	return []SemVer{
		{major: 1, minor: 6},
		{major: 1, minor: 5},
		{major: 1, minor: 4},
		{major: 1, minor: 3},
		{major: 1, minor: 2},
		{major: 1, minor: 1},
		{major: 1, minor: 0},
	}
}

// GitCommit returns the git commit hash and timestamp from build info.
func GitCommit() (hash string, timestamp string) {
	hash, timestamp = "unknown", "unknown"
	hashLen := 7

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return hash, timestamp
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) < hashLen {
				hashLen = len(s.Value)
			}

			hash = s.Value[:hashLen]
		case "vcs.time":
			timestamp = s.Value
		default:
		}
	}

	return hash, timestamp
}

// LogInfo logs charon version information along-with the provided message.
func LogInfo(ctx context.Context, msg string) {
	gitHash, gitTimestamp := GitCommit()
	log.Info(ctx, msg,
		z.Str("version", Version.String()),
		z.Str("git_commit_hash", gitHash),
		z.Str("git_commit_time", gitTimestamp),
	)
}

type semVerType int

const (
	typeMinor semVerType = iota
	typePatch
	typePreRelease
)

// SemVer represents a semantic version. A valid SemVer contains a major and minor version
// and optionally either a typePatch version or a pre-release label, i.e., v1.2 or v1.2.3 or v1.2-rc.
type SemVer struct {
	semVerType semVerType
	major      int
	minor      int
	patch      int
	preRelease string
}

// String returns the string representation of the semantic version.
func (v SemVer) String() string {
	switch v.semVerType {
	case typeMinor:
		return fmt.Sprintf("v%d.%d", v.major, v.minor)
	case typePatch:
		return fmt.Sprintf("v%d.%d.%d", v.major, v.minor, v.patch)
	default:
		return fmt.Sprintf("v%d.%d.%d-%s", v.major, v.minor, v.patch, v.preRelease)
	}
}

// PreRelease returns true if v represents a tag for a pre-release.
func (v SemVer) PreRelease() bool {
	return v.semVerType == typePreRelease
}

// Minor returns the minor version of the semantic version.
// It strips the typePatch version and pre-release label if present.
func (v SemVer) Minor() SemVer {
	return SemVer{
		semVerType: typeMinor,
		major:      v.major,
		minor:      v.minor,
	}
}

// Compare returns an integer comparing two semantic versions.
// Only major and minor versions are used for comparison, unless both a and b
// have patch versions, in which case the patch version is also used.
// Pre-release labels are ignored.
//
// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func Compare(a, b SemVer) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}

		return 1
	}

	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}

		return 1
	}

	if a.semVerType != typePatch || b.semVerType != typePatch {
		return 0
	}

	if a.patch == b.patch {
		return 0
	} else if a.patch < b.patch {
		return -1
	}

	return 1
}

var semverRegex = regexp.MustCompile(`^v(\d+)\.(\d+)(?:\.(\d+))?(?:-(.+))?$`)

// Parse parses a semantic version string into a SemVer.
func Parse(version string) (SemVer, error) {
	matches := semverRegex.FindStringSubmatch(version)
	if len(matches) == 0 || len(matches) != 5 {
		return SemVer{}, errors.New("invalid version string", z.Str("version", version))
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])

	var (
		patch      int
		preRelease string
		typ        = typeMinor
	)

	// If there is a patch version
	if matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
		typ = typePatch
	}

	// If there is a pre-release label
	if matches[4] != "" {
		preRelease = matches[4]
		typ = typePreRelease
	}

	return SemVer{
		major:      major,
		minor:      minor,
		patch:      patch,
		preRelease: preRelease,
		semVerType: typ,
	}, nil
}
