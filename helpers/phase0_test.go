// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/crypto"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var attnData = phase0.AttestationData{
	Slot:            123,
	Index:           3,
	BeaconBlockRoot: phase0.Root{0x01, 0x02, 0x03},
	Source: &phase0.Checkpoint{
		Epoch: 1,
		Root:  phase0.Root{0x10, 0x20, 0x30},
	},
	Target: &phase0.Checkpoint{
		Epoch: 2,
		Root:  phase0.Root{0x30, 0x31, 0x32},
	},
}

var tssParamsJSON = `{
	"commits": [
		"95ecae0e686d506c98a7380a660811bfa7c2c897c990329a4f5eae2610f57e1310e0e7b6c4515d98e176569d4e6d85ae",
		"8a19d5cd73261c13ead1b7ae4a5de5fa22a50bea7fc00fa2e093cad3027fdcca81b00ce9395099cd54c7f13d0e98833f",
		"8e8c33f8b2c955577eac52e416cabea1f3fd7ad7016381f1907d00e5152af00710f05c304a4cf3cb165cad7a1af65eb8"
	],
	"n": 4
}`

var attnSig0 = phase0.BLSSignature{
	0xa9, 0x77, 0x98, 0x14, 0x1f, 0xb0, 0xc6, 0xe2, 0x7d, 0x9f, 0x32, 0x40,
	0x2f, 0xbd, 0x9f, 0x9a, 0xc8, 0x0a, 0x0b, 0x2c, 0xc2, 0x0d, 0x9d, 0xaf,
	0xf3, 0x7a, 0x66, 0x2f, 0x37, 0xeb, 0x99, 0xbe, 0x72, 0xa4, 0x8b, 0x61,
	0xdd, 0xf0, 0xdb, 0x4b, 0x37, 0xae, 0x4e, 0x4d, 0x14, 0x84, 0x5f, 0x5e,
	0x05, 0x7b, 0x3f, 0xcd, 0x4e, 0x86, 0x31, 0xa4, 0x1c, 0x42, 0xbc, 0xec,
	0xf6, 0x26, 0xb1, 0xde, 0xce, 0x13, 0x1a, 0x7e, 0x4c, 0x11, 0xd7, 0x4f,
	0xe0, 0x47, 0x55, 0x4a, 0x55, 0xc1, 0xba, 0xe1, 0x60, 0x9b, 0xdb, 0xe5,
	0xc4, 0x05, 0x10, 0xa3, 0x1b, 0x9b, 0x98, 0x27, 0xc2, 0x52, 0xbb, 0x83,
}

var attnSig1 = phase0.BLSSignature{
	0x8c, 0xda, 0xe3, 0xcc, 0x07, 0x84, 0x8a, 0xe6, 0x3d, 0x4e, 0x95, 0x8b,
	0x1e, 0x5f, 0x1f, 0xfc, 0xca, 0x8b, 0x81, 0xa3, 0xd1, 0xb7, 0x18, 0xc8,
	0xbb, 0x5f, 0x6f, 0x3b, 0x48, 0xe7, 0xe9, 0xca, 0x97, 0x83, 0x86, 0xca,
	0x4b, 0x81, 0x5f, 0x9f, 0x26, 0x4f, 0x5a, 0x22, 0x59, 0xf5, 0x9a, 0x23,
	0x18, 0x18, 0xb9, 0xdc, 0x20, 0xd3, 0x79, 0x24, 0x68, 0xa4, 0x98, 0x27,
	0x3e, 0xde, 0x2a, 0x8e, 0x5c, 0xcb, 0xaf, 0xe6, 0xa6, 0x3a, 0x09, 0x0e,
	0xc1, 0x62, 0xe9, 0xbe, 0x6e, 0xe6, 0x67, 0x87, 0x8f, 0xac, 0x6b, 0x57,
	0xb6, 0x8b, 0xac, 0xec, 0x8a, 0x3d, 0x56, 0x2e, 0x5b, 0x6c, 0x56, 0x82,
}

var attnSig2 = phase0.BLSSignature{
	0x97, 0x8a, 0x6a, 0x85, 0xa6, 0x1b, 0x0b, 0xc3, 0xcf, 0xdc, 0x54, 0x4a,
	0x60, 0x71, 0xa8, 0xf2, 0x57, 0x36, 0xea, 0x75, 0xe7, 0x50, 0xf6, 0x9a,
	0x1d, 0x18, 0xf1, 0x4c, 0x06, 0x28, 0xf3, 0x9d, 0x1d, 0xd7, 0x84, 0x74,
	0xc4, 0x7a, 0x59, 0xff, 0xf3, 0x2e, 0x1a, 0xd4, 0x1a, 0xb0, 0x55, 0xdd,
	0x13, 0xb8, 0x63, 0x19, 0x99, 0x07, 0xcf, 0xe7, 0xc5, 0xce, 0x97, 0x6b,
	0xc4, 0x5d, 0x4f, 0xca, 0x05, 0xc1, 0x9e, 0x84, 0x3c, 0x35, 0x9d, 0xa7,
	0x0d, 0xee, 0xf0, 0xb2, 0x2d, 0x79, 0x6e, 0xa6, 0x65, 0x0a, 0xf6, 0x49,
	0x8f, 0x6b, 0x60, 0x61, 0x93, 0x8d, 0xd8, 0xb3, 0x9d, 0x33, 0xcf, 0x90,
}

var attnSig3 = phase0.BLSSignature{
	0x97, 0x5f, 0xea, 0x4d, 0xb8, 0xe9, 0x41, 0x78, 0x73, 0xd4, 0xed, 0x3a,
	0x2e, 0x29, 0xa5, 0xe4, 0xc2, 0xa1, 0xca, 0xc6, 0x36, 0x54, 0x49, 0x48,
	0x41, 0xde, 0xf4, 0x10, 0x60, 0x25, 0x32, 0xc4, 0x63, 0x75, 0xfd, 0xc6,
	0xea, 0x15, 0xe2, 0x48, 0x8b, 0x2b, 0xb8, 0x32, 0x83, 0x30, 0xbc, 0x5d,
	0x05, 0x7a, 0xc0, 0x25, 0xa0, 0x49, 0x53, 0x10, 0x34, 0x2b, 0xda, 0x67,
	0xe3, 0xde, 0x2d, 0xd3, 0x52, 0x65, 0x09, 0xe0, 0x36, 0xe5, 0xe1, 0x58,
	0x00, 0xca, 0x97, 0x42, 0x8e, 0xb9, 0xe9, 0x8a, 0xfd, 0xfb, 0xed, 0xcd,
	0xf7, 0x9f, 0x17, 0xdd, 0x7a, 0xb9, 0xd1, 0xf5, 0x16, 0xae, 0x6e, 0x68,
}

func TestThresholdAggregateAttestations(t *testing.T) {
	var scheme crypto.TBLSParams
	err := json.Unmarshal([]byte(tssParamsJSON), &scheme)
	require.NoError(t, err)

	newAttestation := func(sig phase0.BLSSignature) *phase0.Attestation {
		aggregationBits := bitfield.NewBitlist(128)
		aggregationBits.SetBitAt(4, true)
		return &phase0.Attestation{
			AggregationBits: aggregationBits,
			Data:            &attnData,
			Signature:       sig,
		}
	}
	attns := []*phase0.Attestation{
		newAttestation(attnSig0),
		newAttestation(attnSig1),
		newAttestation(attnSig2),
		newAttestation(attnSig3),
	}
	indices := []int{0, 1, 2, 3}

	log := zerolog.New(zerolog.NewTestWriter(t))
	finalAttn, err := ThresholdAggregateAttestations(attns, indices, &scheme, &log)
	require.NoError(t, err)
	require.NotNil(t, finalAttn)

	// TODO(dhruv): Test if Prysm accepts the signature
}
