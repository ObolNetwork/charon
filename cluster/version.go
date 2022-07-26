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

const (
	currentVersion = v1_1
	dkgAlgo        = "default"

	v1_2 = "v1.2.0" // WIP
	v1_1 = "v1.1.0"
	v1_0 = "v1.0.0"
)

var supportedVersions = map[string]bool{
	v1_2: true,
	v1_1: true,
	v1_0: true,
}

func isJSONv1x1(version string) bool {
	return version == v1_0 || version == v1_1
}

func isJSONv1x2(version string) bool {
	return version == v1_2
}
