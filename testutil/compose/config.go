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

package compose

import (
	"github.com/obolnetwork/charon/cluster"
)

const (
	version           = "obol/charon/compose/1.0.0"
	composeFile       = "compose.yml"
	defaultImageTag   = "latest"
	defaultBeaconNode = "mock"
	defaultNumVals    = 1
	defaultNumNodes   = 4
	defaultThreshold  = 3
)

// vcType defines a validator client type.
type vcType string

const (
	vcMock       vcType = "mock"
	vcTeku       vcType = "teku"
	vcLighthouse vcType = "lighthouse"
)

// keyGen defines a key generation process.
type keyGen string

const (
	keyGenDKG    keyGen = "dkg"
	keyGenCreate keyGen = "create"
	keyGenSplit  keyGen = "split"
)

// config defines a local compose cluster; including both keygen and running a cluster.
type config struct {
	// Version defines the compose config version.
	Version string `json:"version"`

	// ImageTag defines the charon docker image tag: ghcr.io/obolnetwork/charon:{ImageTag}.
	ImageTag string `json:"image_tag"`

	// VCs define the types of validator clients to use.
	VCs []vcType `json:"validator_clients"`

	// keyGen defines the key generation process.
	KeyGen keyGen `json:"key_gen"`

	// BeaconNode url endpoint or "mock" for simnet.
	BeaconNode string `json:"beacon_node"`

	// Def is the cluster definition.
	Def cluster.Definition `json:"definition"`
}

// newDefaultConfig returns a new default config excluding cluster definition.
func newDefaultConfig() config {
	return config{
		Version:    version,
		ImageTag:   defaultImageTag,
		VCs:        []vcType{vcTeku, vcLighthouse, vcMock},
		KeyGen:     keyGenDKG,
		BeaconNode: defaultBeaconNode,
	}
}
