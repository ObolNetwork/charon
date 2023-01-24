// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cluster

import "testing"

const (
	currentVersion = v1_4
	dkgAlgo        = "default"

	v1_5 = "v1.5.0" // Draft
	v1_4 = "v1.4.0" // Default
	v1_3 = "v1.3.0"
	v1_2 = "v1.2.0"
	v1_1 = "v1.1.0"
	v1_0 = "v1.0.0"

	zeroNonce = 0
)

var supportedVersions = map[string]bool{
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

func isV1x0(version string) bool {
	return version == v1_0
}

func isV1x1(version string) bool {
	return version == v1_1
}

func isV1x2(version string) bool {
	return version == v1_2
}

func isV1x3(version string) bool {
	return version == v1_3
}

func isV1x4(version string) bool {
	return version == v1_4
}

func isV1x5(version string) bool {
	return version == v1_5
}

// SupportedVersionsForT returns the supported definition versions for testing purposes only.
func SupportedVersionsForT(*testing.T) []string {
	var resp []string
	for version := range supportedVersions {
		resp = append(resp, version)
	}

	return resp
}
