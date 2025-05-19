// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"regexp"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

var (
	minLighthouseVersion, _ = version.Parse("v7.0.0")
	minTekuVersion, _       = version.Parse("v25.4.1")
	minLodestarVersion, _   = version.Parse("v1.29.0")
	minNimbusVersion, _     = version.Parse("v25.4.1")
	minPrysmVersion, _      = version.Parse("v6.0.0")

	minimumBeaconNodeVersion = map[string]version.SemVer{
		"Lighthouse": minLighthouseVersion,
		"teku":       minTekuVersion,
		"Lodestar":   minLodestarVersion,
		"Nimbus":     minNimbusVersion,
		"Prysm":      minPrysmVersion,
	}
)

type BeaconNodeVersionStatus int

const (
	VersionOK BeaconNodeVersionStatus = iota
	VersionFormatError
	VersionUnknownClient
	VersionTooOld
)

var versionExtractRegex = regexp.MustCompile(`^([^/]+)/v?([0-9]+\.[0-9]+\.[0-9]+)`)

// CheckBeaconNodeVersionStatus checks the version of the beacon node client against the minimum required version.
// It returns the status of the version check as an enum, the current version, and the minimum required version.
func checkBeaconNodeVersionStatus(bnVersion string) (BeaconNodeVersionStatus, string, string) {
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

	return VersionOK, clientVersion.String(), minVersion.String()
}

// CheckBeaconNodeVersion checks the version of the beacon node client and logs a warning if the version is below the minimum
// or if the client is not recognized.
func CheckBeaconNodeVersion(ctx context.Context, bnVersion string) {
	status, current, min := checkBeaconNodeVersionStatus(bnVersion)

	switch status {
	case VersionFormatError:
		log.Warn(ctx, "Failed to parse beacon node version string due to unexpected format",
			nil, z.Str("input", bnVersion))
	case VersionUnknownClient:
		log.Warn(ctx, "Unknown beacon node client not in supported client list",
			nil, z.Str("client", bnVersion))
	case VersionTooOld:
		log.Warn(ctx, "Beacon node client version is below the minimum supported version. Please upgrade your beacon node.",
			nil, z.Str("client_version", current), z.Str("minimum_required", min))
	}
}
