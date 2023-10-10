// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"encoding/json"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestSignedDataSetSignature(t *testing.T) {
	tests := []struct {
		name string
		data core.SignedData
	}{
		{
			name: "versioned signed beacon block",
			data: core.VersionedSignedBeaconBlock{
				VersionedSignedBeaconBlock: eth2spec.VersionedSignedBeaconBlock{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &bellatrix.SignedBeaconBlock{
						Message:   testutil.RandomBellatrixBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed blinded beacon block bellatrix",
			data: core.VersionedSignedBlindedBeaconBlock{
				VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
						Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed blinded beacon block capella",
			data: core.VersionedSignedBlindedBeaconBlock{
				VersionedSignedBlindedBeaconBlock: eth2api.VersionedSignedBlindedBeaconBlock{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2capella.SignedBlindedBeaconBlock{
						Message:   testutil.RandomCapellaBlindedBeaconBlock(),
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
			data: core.NewSignedSyncContributionAndProof(testutil.RandomSignedSyncContributionAndProof()),
		},
		{
			name: "signed sync committee selection",
			data: core.NewSyncCommitteeSelection(testutil.RandomSyncCommitteeSelection()),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone, err := test.data.SetSignatures([]core.Signature{testutil.RandomCoreSignature()})
			require.NoError(t, err)
			require.NotEqual(t, clone.Signatures(), test.data.Signatures())
			require.NotEmpty(t, clone.Signatures())

			msgRoot, err := test.data.MessageRoots()
			require.NoError(t, err)
			cloneRoot, err := test.data.MessageRoots()
			require.NoError(t, err)
			require.Equal(t, msgRoot, cloneRoot)
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
