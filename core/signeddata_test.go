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

package core_test

import (
	"encoding/json"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestSignedDataSetSignature(t *testing.T) {
	const nonZero = 123

	tests := []struct {
		name string
		data core.SignedData
	}{
		{
			name: "version signed beacon block",
			data: core.VersionedSignedBeaconBlock{
				VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
					Version: spec.DataVersionBellatrix,
					Bellatrix: &bellatrix.SignedBeaconBlock{
						Message:   testutil.RandomBellatrixBeaconBlock(t),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "version signed blinded beacon block",
			data: core.VersionedSignedBlindedBeaconBlock{
				VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
					Version: spec.DataVersionBellatrix,
					Bellatrix: &eth2v1.SignedBlindedBeaconBlock{
						Message:   testutil.RandomBellatrixBlindedBeaconBlock(t),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed beacon committee selection",
			data: testutil.RandomCoreBeaconCommitteeSelection(),
		},
		{
			name: "signed aggregate and proof",
			data: core.SignedAggregateAndProof{
				SignedAggregateAndProof: eth2p0.SignedAggregateAndProof{
					Message: &eth2p0.AggregateAndProof{
						AggregatorIndex: 0,
						Aggregate:       testutil.RandomAttestation(),
						SelectionProof:  testutil.RandomEth2Signature(),
					},
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "signed sync committee message",
			data: core.SignedSyncMessage{
				SyncCommitteeMessage: altair.SyncCommitteeMessage{
					Slot:            testutil.RandomSlot(),
					BeaconBlockRoot: testutil.RandomRoot(),
					ValidatorIndex:  testutil.RandomVIdx(),
					Signature:       testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "signed sync contribution",
			data: core.SignedSyncContributionAndProof{
				SignedContributionAndProof: testutil.RandomSignedSyncContributionAndProof(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone, err := test.data.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)
			require.NotEqual(t, clone.Signature(), test.data.Signature())
			require.NotEmpty(t, clone.Signature())
		})
	}
}

func TestMarshalSubscription(t *testing.T) {
	selection := testutil.RandomCoreBeaconCommitteeSelection()
	b, err := json.Marshal(selection)
	require.NoError(t, err)

	var selection2 core.BeaconCommitteeSelection
	err = json.Unmarshal(b, &selection2)
	require.NoError(t, err)
	require.Equal(t, selection2, selection)
}
