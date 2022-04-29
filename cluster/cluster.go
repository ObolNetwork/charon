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

// Package cluster provides the cluster configuration API. It defines the `Definition` type that is
// the output of the Launchpad and `charon create dkg` commands.
// `Definition` is also the input to `charon dkg`. If defines the `Lock` type that is
// the output of the `charon dkg` and `charon create cluster` commands. `Lock` is also the input
// to `charon run` command.
//
//  launchpad.obol.net ─┐
//                      ├─► cluster_definition.json ──► charon dkg ─┐
//   charon create dkg ─┘                                           ├─► cluster_lock.json ──► charon run
//                                           charon create cluster ─┘
package cluster

import (
	"fmt"
	"io"
)

const (
	definitionVersion = "v1.0.0"
	dkgAlgo           = "default"
)

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
