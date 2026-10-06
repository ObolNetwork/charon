// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

// Lowercase consensus and validator client names, as used in the version tables.
const (
	clientLighthouse = "lighthouse"
	clientTeku       = "teku"
	clientLodestar   = "lodestar"
	clientNimbus     = "nimbus"
	clientPrysm      = "prysm"
	clientGrandine   = "grandine"
	clientVouch      = "vouch"
)

var (
	minLighthouseVersion, _ = version.Parse("v8.0.0-rc.0")
	minTekuVersion, _       = version.Parse("v25.9.3")
	minLodestarVersion, _   = version.Parse("v1.35.0-rc.1")
	minNimbusVersion, _     = version.Parse("v25.9.2")
	minPrysmVersion, _      = version.Parse("v6.1.0")
	minGrandineVersion, _   = version.Parse("v2.0.0.rc0")

	minimumBeaconNodeVersion = map[string]version.SemVer{
		clientLighthouse: minLighthouseVersion,
		clientTeku:       minTekuVersion,
		clientLodestar:   minLodestarVersion,
		clientNimbus:     minNimbusVersion,
		clientPrysm:      minPrysmVersion,
		clientGrandine:   minGrandineVersion,
	}

	incompatibleBeaconNodeVersion = map[string][]version.SemVer{}

	// The following tables define the minimum client versions required to support a scheduled
	// fork, keyed by lowercase client name. Clients absent from a fork's map have an unknown fork
	// readiness, unless the fork has no map.

	// minimumBeaconNodeVersionByFork defines the minimum beacon node versions per fork.
	minimumBeaconNodeVersionByFork = map[Fork]map[string]forkVersion{
		Gloas: {
			clientLighthouse: mustParseForkVersion("v8.3.0-rc.0"),
			clientTeku:       mustParseForkVersion("v26.9.1"),
			clientLodestar:   mustParseForkVersion("v1.49.0"),
			clientNimbus:     mustParseForkVersion("v26.10.0"),
			clientPrysm:      mustParseForkVersion("v7.2.1"),
		},
	}

	// minimumValidatorClientVersionByFork defines the minimum validator client versions per fork.
	minimumValidatorClientVersionByFork = map[Fork]map[string]forkVersion{
		Gloas: {
			clientLighthouse: mustParseForkVersion("v8.3.0-rc.0"),
			clientTeku:       mustParseForkVersion("v26.9.1"),
			clientLodestar:   mustParseForkVersion("v1.49.0"),
			clientNimbus:     mustParseForkVersion("v26.10.0"),
			clientPrysm:      mustParseForkVersion("v7.2.1"),
		},
	}

	// minimumExecutionEngineVersionByFork defines the minimum execution engine versions per fork,
	// keyed by the engine_getClientVersionV1 client name.
	minimumExecutionEngineVersionByFork = map[Fork]map[string]forkVersion{
		Gloas: {
			"besu":        mustParseForkVersion("v26.9.0"),
			"go-ethereum": mustParseForkVersion("v1.17.7"),
			"erigon":      mustParseForkVersion("v3.7.0"),
			"nethermind":  mustParseForkVersion("v2.1.0"),
			"reth":        mustParseForkVersion("v2.7.0"),
			"nimbus":      mustParseForkVersion("v0.4.2"),
			"ethrex":      mustParseForkVersion("v28.0.0"),
		},
	}

	// The following tables define known issues of fork supporting client versions per fork.

	// knownBeaconNodeIssuesByFork defines known beacon node issues per fork.
	knownBeaconNodeIssuesByFork = map[Fork]map[string]knownIssue{}

	// knownValidatorClientIssuesByFork defines known validator client issues per fork.
	knownValidatorClientIssuesByFork = map[Fork]map[string]knownIssue{
		Gloas: {
			clientTeku: {Description: "missing Eth-Consensus-Version header on proposer preferences (teku#11373) and payload attestations (teku#11406)"},
		},
	}

	// knownExecutionEngineIssuesByFork defines known execution engine issues per fork.
	knownExecutionEngineIssuesByFork = map[Fork]map[string]knownIssue{}

	// validatorClients are the lowercase names of known validator clients, used to tell validator
	// client user agents apart from other API users, e.g. monitoring tools and scripts.
	validatorClients = map[string]bool{
		clientLighthouse: true,
		clientTeku:       true,
		clientLodestar:   true,
		clientNimbus:     true,
		clientPrysm:      true,
		clientVouch:      true,
	}

	// clientNameAliases maps lowercase client name variants to the fork table keys.
	clientNameAliases = map[string]string{
		"geth": "go-ethereum",
	}
)

// knownIssue is a known issue of a client affecting a fork.
type knownIssue struct {
	// Description of the issue.
	Description string
	// FixedIn is the first client version fixing the issue, zero if not fixed yet.
	FixedIn forkVersion
}

// Pre-release ranks of a fork version, ordered by precedence. Zero denotes an unset version.
const (
	preReleaseAlpha = iota + 1
	preReleaseBeta
	preReleaseRC
	preReleaseNone
)

// forkVersionRegex extracts the client name, version and optional alpha, beta or rc pre-release
// label with number (e.g. "-rc.1", "-rc1", "-rc-1", ".rc1") from a client version string. Other
// suffixes, like commit hashes, are ignored.
var forkVersionRegex = regexp.MustCompile(`^(?:([^/]+)/)?v?(\d+)\.(\d+)\.(\d+)(?:[-.]?((?i:alpha|beta|rc))[-.]?(\d+)?)?`)

// forkVersion is a client version compared with patch and pre-release precedence.
type forkVersion struct {
	major, minor, patch int
	// preRelease is the pre-release rank, preReleaseNone for releases.
	preRelease int
	// preReleaseNum is the pre-release number, zero if absent.
	preReleaseNum int
}

// String returns the version, formatted as "vX.Y.Z[-label.N]".
func (v forkVersion) String() string {
	resp := fmt.Sprintf("v%d.%d.%d", v.major, v.minor, v.patch)

	switch v.preRelease {
	case preReleaseAlpha:
		resp += fmt.Sprintf("-alpha.%d", v.preReleaseNum)
	case preReleaseBeta:
		resp += fmt.Sprintf("-beta.%d", v.preReleaseNum)
	case preReleaseRC:
		resp += fmt.Sprintf("-rc.%d", v.preReleaseNum)
	default:
	}

	return resp
}

// parseClientForkVersion parses a client version string, formatted "[Name/]vX.Y.Z...", returning
// the client name and version.
func parseClientForkVersion(clientVersion string) (string, forkVersion, bool) {
	matches := forkVersionRegex.FindStringSubmatch(clientVersion)
	if len(matches) != 7 {
		return "", forkVersion{}, false
	}

	atoi := func(s string) int {
		resp, _ := strconv.Atoi(s)
		return resp
	}

	resp := forkVersion{
		major:         atoi(matches[2]),
		minor:         atoi(matches[3]),
		patch:         atoi(matches[4]),
		preRelease:    preReleaseNone,
		preReleaseNum: atoi(matches[6]),
	}

	switch strings.ToLower(matches[5]) {
	case "alpha":
		resp.preRelease = preReleaseAlpha
	case "beta":
		resp.preRelease = preReleaseBeta
	case "rc":
		resp.preRelease = preReleaseRC
	default:
	}

	return matches[1], resp, true
}

// IsValidatorClientUserAgent returns true if the user agent, formatted "Name/vX.Y.Z...", belongs to a
// known validator client.
func IsValidatorClientUserAgent(userAgent string) bool {
	name, _, ok := strings.Cut(userAgent, "/")

	return ok && validatorClients[strings.ToLower(name)]
}

// mustParseForkVersion parses a static version string, panicking if it is invalid.
func mustParseForkVersion(v string) forkVersion {
	_, resp, ok := parseClientForkVersion(v)
	if !ok {
		panic("invalid fork version: " + v)
	}

	return resp
}

// compareForkVersions returns -1, 0 or 1 if a is lower than, equal to or greater than b.
func compareForkVersions(a, b forkVersion) int {
	return cmp.Or(
		cmp.Compare(a.major, b.major),
		cmp.Compare(a.minor, b.minor),
		cmp.Compare(a.patch, b.patch),
		cmp.Compare(a.preRelease, b.preRelease),
		cmp.Compare(a.preReleaseNum, b.preReleaseNum),
	)
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

	client := strings.ToLower(matches[1])

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
func checkClientForkSupport(minVersions map[string]forkVersion, issues map[string]knownIssue, clientVersion string,
) (status string, clVer string, minVer string, issue string) {
	name, parsed, ok := parseClientForkVersion(clientVersion)
	if !ok || name == "" {
		return forkStatusUnknown, "", "", ""
	}

	client := strings.ToLower(name)
	if alias, ok := clientNameAliases[client]; ok {
		client = alias
	}

	if len(minVersions) == 0 {
		// No expectations set for this fork, e.g. a past fork.
		return forkStatusReady, parsed.String(), "", ""
	}

	minVersion, ok := minVersions[client]
	if !ok {
		// No expectation set for this client.
		return forkStatusUnknown, parsed.String(), "", ""
	}

	if compareForkVersions(parsed, minVersion) < 0 {
		return forkStatusUpgradeRequired, parsed.String(), minVersion.String(), ""
	}

	known, ok := issues[client]
	if ok && (known.FixedIn == forkVersion{} || compareForkVersions(parsed, known.FixedIn) < 0) {
		return forkStatusKnownIssues, parsed.String(), minVersion.String(), known.Description
	}

	return forkStatusReady, parsed.String(), minVersion.String(), ""
}
