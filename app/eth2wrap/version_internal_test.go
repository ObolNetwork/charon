// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
)

func TestCheckBeaconNodeVersionStatus(t *testing.T) {
	cases := []struct {
		versionStr string
		wantStatus BeaconNodeVersionStatus
	}{
		// Teku
		{"teku/v25.4.1/linux-x86_64/-eclipseadoptium-openjdk64bitservervm-java-21", VersionOK},
		{"teku/vUNKNOWN+g40561a9/linux-x86_64/-eclipseadoptium-openjdk64bitservervm-java-21", VersionFormatError},

		// Lighthouse
		{"Lighthouse/v7.0.1-e42406d/x86_64-linux", VersionOK},
		{"Lighthouse/v7.0.0-54f7bc5/aarch64-linux", VersionOK},

		// Lodestar
		{"Lodestar/v1.29.0/8335180", VersionOK},
		{"Lodestar/v1.30.0/1a34f98", VersionOK},

		// Nimbus
		{"Nimbus/v25.4.1-77cfa7-stateofus", VersionOK},
		{"Nimbus/v25.5.0-d2f233-stateofus", VersionOK},
		{"Nimbus/v25.4.0-c7e5ca-stateofus", VersionTooOld},

		// Prysm
		{"Prysm/v5.3.2 (linux amd64)", VersionTooOld},
		{"Prysm/v6.0.2 (linux amd64)", VersionOK},
		{"Prysm/v6.0.0 (linux amd64)", VersionOK},

		// Grandine
		{"Grandine/1.1.0-29cb5c1/x86_64-linux2025-05-19", VersionOK},

		// Additional error cases
		{"", VersionFormatError},
		{"justastring", VersionFormatError},
		{"/v7.0.0", VersionFormatError},
		{"UnknownClient/v7.0.0", VersionUnknownClient},
		{"Lighthouse/", VersionFormatError},
		{"Lighthouse/vBAD", VersionFormatError},
	}

	// Redefine minimum versions here to be independent of future changes
	minLighthouseVersion, _ = version.Parse("v7.0.0")
	minTekuVersion, _ = version.Parse("v25.4.1")
	minLodestarVersion, _ = version.Parse("v1.29.0")
	minNimbusVersion, _ = version.Parse("v25.4.1")
	minPrysmVersion, _ = version.Parse("v6.0.0")
	minGrandineVersion, _ = version.Parse("v1.1.0")

	minimumBeaconNodeVersion = map[string]version.SemVer{
		"Lighthouse": minLighthouseVersion,
		"teku":       minTekuVersion,
		"Lodestar":   minLodestarVersion,
		"Nimbus":     minNimbusVersion,
		"Prysm":      minPrysmVersion,
		"Grandine":   minGrandineVersion,
	}

	for _, tc := range cases {
		t.Run(tc.versionStr, func(t *testing.T) {
			status, _, _ := checkBeaconNodeVersionStatus(tc.versionStr)
			require.Equal(t, tc.wantStatus, status)
		})
	}
}
