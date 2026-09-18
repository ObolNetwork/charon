// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

// builderConfigured returns true if builder URLs are configured, enabling the builder
// section of the proposer configuration output. The other builder flags are rejected
// without URLs, so they cannot be set (and silently dropped) on their own.
func builderConfigured(conf Config) bool {
	return len(conf.BuilderURLs) > 0
}
