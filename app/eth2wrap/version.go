// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"regexp"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

var (
	minLighthouseVersion, _ = version.Parse("v8.0.0-rc.0")
	minTekuVersion, _       = version.Parse("v25.9.3")
	minLodestarVersion, _   = version.Parse("v1.35.0-rc.1")
	minNimbusVersion, _     = version.Parse("v25.9.2")
	minPrysmVersion, _      = version.Parse("v6.1.0")
	minGrandineVersion, _   = version.Parse("v2.0.0.rc0")

	minimumBeaconNodeVersion = map[string]version.SemVer{
		"Lighthouse": minLighthouseVersion,
		"teku":       minTekuVersion,
		"Lodestar":   minLodestarVersion,
		"Nimbus":     minNimbusVersion,
		"Prysm":      minPrysmVersion,
		"Grandine":   minGrandineVersion,
	}

	incompatibleBeaconNodeVersion = map[string][]version.SemVer{}

	// The following tables define the minimum client versions required to support a scheduled
	// fork. Clients absent from a fork's map have an unknown fork readiness, unless the fork has no map.

	// minimumBeaconNodeVersionByFork defines the minimum beacon node versions per fork.
	minimumBeaconNodeVersionByFork = map[Fork]map[string]version.SemVer{
		Gloas: {
			"Lighthouse": mustParseVersion("v8.3.0-rc.0"),
			"teku":       mustParseVersion("v26.9.1"),
			"Lodestar":   mustParseVersion("v1.49.0"),
			"Nimbus":     mustParseVersion("v26.10.0"),
			"Prysm":      mustParseVersion("v7.2.1"),
		},
	}

	// minimumValidatorClientVersionByFork defines the minimum validator client versions per fork.
	minimumValidatorClientVersionByFork = map[Fork]map[string]version.SemVer{
		Gloas: {
			"Lighthouse": mustParseVersion("v8.3.0-rc.0"),
			"teku":       mustParseVersion("v26.9.1"),
			"Lodestar":   mustParseVersion("v1.49.0"),
			"Nimbus":     mustParseVersion("v26.10.0"),
			"Prysm":      mustParseVersion("v7.2.1"),
		},
	}

	// minimumExecutionEngineVersionByFork defines the minimum execution engine versions per fork,
	// keyed by the engine_getClientVersionV1 client name.
	minimumExecutionEngineVersionByFork = map[Fork]map[string]version.SemVer{
		Gloas: {
			"Besu":        mustParseVersion("v26.9.0"),
			"go-ethereum": mustParseVersion("v1.17.7"),
			"erigon":      mustParseVersion("v3.7.0"),
			"Nethermind":  mustParseVersion("v2.1.0"),
			"Reth":        mustParseVersion("v2.7.0"),
			"Nimbus":      mustParseVersion("v0.4.2"),
			"ethrex":      mustParseVersion("v28.0.0"),
		},
	}

	// The following tables define known issues of fork supporting client versions per fork.

	// knownBeaconNodeIssuesByFork defines known beacon node issues per fork.
	knownBeaconNodeIssuesByFork = map[Fork]map[string]knownIssue{}

	// knownValidatorClientIssuesByFork defines known validator client issues per fork.
	knownValidatorClientIssuesByFork = map[Fork]map[string]knownIssue{
		Gloas: {
			"teku": {Description: "missing Eth-Consensus-Version header on proposer preferences (teku#11373) and payload attestations (teku#11406)"},
		},
	}

	// knownExecutionEngineIssuesByFork defines known execution engine issues per fork.
	knownExecutionEngineIssuesByFork = map[Fork]map[string]knownIssue{}
)

// knownIssue is a known issue of a client affecting a fork.
type knownIssue struct {
	// Description of the issue.
	Description string
	// FixedIn is the first client version fixing the issue, zero if not fixed yet.
	FixedIn version.SemVer
}

// mustParseVersion parses a static version string, panicking if it is invalid.
func mustParseVersion(v string) version.SemVer {
	resp, err := version.Parse(v)
	if err != nil {
		panic(err)
	}

	return resp
}

type BeaconNodeVersionStatus int

const (
	VersionOK BeaconNodeVersionStatus = iota
	VersionFormatError
	VersionUnknownClient
	VersionTooOld
	VersionIncompatible
)

var versionExtractRegex = regexp.MustCompile(`^([^/]+)/v?([0-9]+\.[0-9]+\.[0-9]+)`)

// checkBeaconNodeVersionStatus checks the version of the beacon node client against the minimum required version and possible incompatible versions.
// It returns the status of the version check as an enum, the current version, and the minimum required version.
func checkBeaconNodeVersionStatus(bnVersion string) (beaconNodeVersionStatus BeaconNodeVersionStatus, clVer string, minVer string) {
	matches := versionExtractRegex.FindStringSubmatch(bnVersion)
	if len(matches) != 3 {
		return VersionFormatError, "", ""
	}

	client := matches[1]

	clientVersion, err := version.Parse("v" + matches[2])
	if err != nil {
		return VersionFormatError, "", ""
	}

	minVersion, ok := minimumBeaconNodeVersion[client]
	if !ok {
		return VersionUnknownClient, "", ""
	}

	if version.Compare(clientVersion, minVersion) == -1 {
		return VersionTooOld, clientVersion.String(), minVersion.String()
	}

	for _, badVer := range incompatibleBeaconNodeVersion[client] {
		if version.Compare(clientVersion, badVer) == 0 {
			return VersionIncompatible, clientVersion.String(), ""
		}
	}

	return VersionOK, clientVersion.String(), minVersion.String()
}

// CheckBeaconNodeVersion checks the version of the beacon node client and logs a warning if the version is below the minimum,
// if its an incompatible version or if the client is not recognized.
func CheckBeaconNodeVersion(ctx context.Context, bnVersion string) {
	status, currentVersion, minVersion := checkBeaconNodeVersionStatus(bnVersion)

	//nolint:revive // enforce-switch-style: the list is exhaustive and there is no need for default
	switch status {
	case VersionFormatError:
		log.Warn(ctx, "Failed to parse beacon node version string due to unexpected format. This may indicate an unsupported or custom beacon node build",
			nil, z.Str("input", bnVersion))
	case VersionUnknownClient:
		log.Warn(ctx, "Unknown beacon node client detected. The client is not in the supported client list and may cause compatibility issues",
			nil, z.Str("client", bnVersion))
	case VersionTooOld:
		log.Warn(ctx, "Beacon node client version is below the minimum supported version. Please upgrade your beacon node to ensure compatibility and security",
			nil, z.Str("client_version", currentVersion), z.Str("minimum_required", minVersion))
	case VersionIncompatible:
		log.Warn(ctx, "Beacon node client version is known to be incompatible with Charon. Please upgrade or downgrade your beacon node to a compatible version",
			nil, z.Str("client_version", currentVersion))
	case VersionOK:
		// Do nothing
	}
}

// checkClientForkSupport checks a client version string (formatted "Name/vX.Y.Z...", as
// published by beacon nodes, execution engines and validator client user agents) against the
// provided per-client fork minimums and known issues. It returns the fork readiness status, the
// current version, the minimum required version and the known issue description, if any.
func checkClientForkSupport(minVersions map[string]version.SemVer, issues map[string]knownIssue, clientVersion string,
) (status string, clVer string, minVer string, issue string) {
	matches := versionExtractRegex.FindStringSubmatch(clientVersion)
	if len(matches) != 3 {
		return forkStatusUnknown, "", "", ""
	}

	parsed, err := version.Parse("v" + matches[2])
	if err != nil {
		return forkStatusUnknown, "", "", ""
	}

	client := matches[1]

	if len(minVersions) == 0 {
		// No expectations set for this fork, e.g. a past fork.
		return forkStatusReady, parsed.String(), "", ""
	}

	minVersion, ok := minVersions[client]
	if !ok {
		// No expectation set for this client.
		return forkStatusUnknown, parsed.String(), "", ""
	}

	if version.Compare(parsed, minVersion) == -1 {
		return forkStatusUpgradeRequired, parsed.String(), minVersion.String(), ""
	}

	known, ok := issues[client]
	if ok && (known.FixedIn == version.SemVer{} || version.Compare(parsed, known.FixedIn) == -1) {
		return forkStatusKnownIssues, parsed.String(), minVersion.String(), known.Description
	}

	return forkStatusReady, parsed.String(), minVersion.String(), ""
}
