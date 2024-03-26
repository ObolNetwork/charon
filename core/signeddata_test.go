// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"encoding/json"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
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
			name: "versioned signed proposal",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &bellatrix.SignedBeaconBlock{
						Message:   testutil.RandomBellatrixBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed blinded proposal bellatrix",
			data: core.VersionedSignedBlindedProposal{
				VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &eth2bellatrix.SignedBlindedBeaconBlock{
						Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed blinded proposal capella",
			data: core.VersionedSignedBlindedProposal{
				VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2capella.SignedBlindedBeaconBlock{
						Message:   testutil.RandomCapellaBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed blinded proposal deneb",
			data: core.VersionedSignedBlindedProposal{
				VersionedSignedBlindedProposal: eth2api.VersionedSignedBlindedProposal{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2deneb.SignedBlindedBeaconBlock{
						Message:   testutil.RandomDenebBlindedBeaconBlock(),
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
			clone, err := test.data.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)
			require.NotEqual(t, clone.Signature(), test.data.Signature())
			require.NotEmpty(t, clone.Signature())

			msgRoot, err := test.data.MessageRoot()
			require.NoError(t, err)
			cloneRoot, err := test.data.MessageRoot()
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

func TestNewPartialSignature(t *testing.T) {
	sig := testutil.RandomCoreSignature()

	partialSig := core.NewPartialSignature(sig, 3)

	require.Equal(t, sig, partialSig.Signature())
	require.Equal(t, 3, partialSig.ShareIdx)
}

func TestSignature(t *testing.T) {
	sig1 := testutil.RandomCoreSignature()

	sig2, err := sig1.Clone()
	require.NoError(t, err)
	require.Equal(t, sig1, sig2)

	_, err = sig1.MessageRoot()
	require.ErrorContains(t, err, "signed message root not supported by signature type")
	require.Equal(t, sig1, sig1.Signature())

	blssig1 := sig1.ToETH2()
	blssig2 := sig2.Signature().ToETH2()
	require.Equal(t, blssig1, blssig2)

	js, err := sig1.MarshalJSON()
	require.NoError(t, err)

	sig3 := &core.Signature{}
	err = sig3.UnmarshalJSON(js)
	require.NoError(t, err)
	require.Equal(t, sig1, *sig3)
}
