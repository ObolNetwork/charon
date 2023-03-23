// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version

import (
	"context"
	"runtime/debug"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// Version is the release version of the codebase.
	// Usually overridden by tag names when building binaries.
	Version = "v0.14.4"
)

// Supported returns the supported versions in order of precedence.
func Supported() []string {
	return []string{
		"v0.14",
		"v0.13",
	}
}

// GitCommit returns the git commit hash and timestamp from build info.
func GitCommit() (hash string, timestamp string) {
	hash, timestamp = "unknown", "unknown"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return hash, timestamp
	}

	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			hash = s.Value[:7]
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
