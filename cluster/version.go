// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import "testing"

const (
	currentVersion = v1_7
	dkgAlgo        = "default"

	v1_8 = "v1.8.0"
	v1_7 = "v1.7.0" // Default
	v1_6 = "v1.6.0"
	v1_5 = "v1.5.0"
	v1_4 = "v1.4.0"
	v1_3 = "v1.3.0"
	v1_2 = "v1.2.0"
	v1_1 = "v1.1.0"
	v1_0 = "v1.0.0"

	zeroNonce = 0

	MinVersionForPartialDeposits = v1_8
)

var supportedVersions = map[string]bool{
	v1_8: true,
	v1_7: true,
	v1_6: true,
	v1_5: true,
	v1_4: true,
	v1_3: true,
	v1_2: true,
	v1_1: true,
	v1_0: true,
}

func isAnyVersion(version string, versions ...string) bool {
	for _, v := range versions {
		if version == v {
			return true
		}
	}

	return false
}

func isV1x3(version string) bool {
	return version == v1_3
}

// SupportedVersionsForT returns the supported definition versions for testing purposes only.
func SupportedVersionsForT(*testing.T) []string {
	var resp []string
	for version := range supportedVersions {
		resp = append(resp, version)
	}

	return resp
}

// SupportPregenRegistrations returns true if the version is v1.7 or later.
func SupportPregenRegistrations(version string) bool {
	return !isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6)
}

// SupportNodeSignatures returns true if the version is v1.7 or later.
func SupportNodeSignatures(version string) bool {
	return !isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6)
}
