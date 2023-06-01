// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version

import (
	"context"
	"runtime/debug"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// Version is the branch version of the codebase.
//   - Main branch: v0.X-dev
//   - Release branch: v0.X-rc
//
// It is overwritten at build-time with the git tag for official releases.
var Version = "v0.16-rc"

// Supported returns the supported minor versions in order of precedence.
func Supported() []string {
	return []string{
		"v0.16", // Current minor version always goes first.
		"v0.15",
		"v0.14",
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
		if s.Key == "vcs.revision" {
			if len(s.Value) < hashLen {
				hashLen = len(s.Value)
			}
			hash = s.Value[:hashLen]
		} else if s.Key == "vcs.time" {
			timestamp = s.Value
		}
	}

	return hash, timestamp
}

// LogInfo logs charon version information along-with the provided message.
func LogInfo(ctx context.Context, msg string) {
	gitHash, gitTimestamp := GitCommit()
	log.Info(ctx, msg,
		z.Str("version", Version),
		z.Str("git_commit_hash", gitHash),
		z.Str("git_commit_time", gitTimestamp),
	)
}

// Minor returns the minor version of the provided version string.
func Minor(version string) (string, error) {
	split := strings.Split(version, ".")
	if len(split) < 2 {
		return "", errors.New("invalid version string")
	}

	major := split[0]

	minor := split[1]
	if split := strings.Split(minor, "-"); len(split) > 1 {
		minor = split[0]
	}

	return major + "." + minor, nil
}
