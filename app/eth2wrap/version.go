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
)

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
