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
	"github.com/attestantio/go-eth2-client/spec/capella"
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

	ss, err := sig1.SetSignature(sig2.Signature())
	require.NoError(t, err)
	require.Equal(t, sig2, ss)

	js, err := sig1.MarshalJSON()
	require.NoError(t, err)

	sig3 := &core.Signature{}
	err = sig3.UnmarshalJSON(js)
	require.NoError(t, err)
	require.Equal(t, sig1, *sig3)
}

func TestNewVersionedSignedProposal(t *testing.T) {
	type testCase struct {
		error   string
		version eth2spec.DataVersion
		blinded bool
	}

	tests := []testCase{
		{
			error:   "unknown version",
			version: eth2spec.DataVersion(999),
		},
		{
			error:   "no phase0 proposal",
			version: eth2spec.DataVersionPhase0,
		},
		{
			error:   "no altair proposal",
			version: eth2spec.DataVersionAltair,
		},
		{
			error:   "no bellatrix proposal",
			version: eth2spec.DataVersionBellatrix,
		},
		{
			error:   "no capella proposal",
			version: eth2spec.DataVersionCapella,
		},
		{
			error:   "no deneb proposal",
			version: eth2spec.DataVersionDeneb,
		},
		{
			error:   "no bellatrix blinded proposal",
			version: eth2spec.DataVersionBellatrix,
			blinded: true,
		},
		{
			error:   "no capella blinded proposal",
			version: eth2spec.DataVersionCapella,
			blinded: true,
		},
		{
			error:   "no deneb blinded proposal",
			version: eth2spec.DataVersionDeneb,
			blinded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.error, func(t *testing.T) {
			_, err := core.NewVersionedSignedProposal(&eth2api.VersionedSignedProposal{
				Version: test.version,
				Blinded: test.blinded,
			})
			require.ErrorContains(t, err, test.error)
		})
	}

	t.Run("happy path", func(t *testing.T) {
		proposal := testutil.RandomBellatrixCoreVersionedSignedProposal()

		p, err := core.NewVersionedSignedProposal(&proposal.VersionedSignedProposal)
		require.NoError(t, err)
		require.Equal(t, proposal, p)
	})
}

func TestNewPartialVersionedSignedProposal(t *testing.T) {
	proposal := testutil.RandomBellatrixCoreVersionedSignedProposal()

	psd, err := core.NewPartialVersionedSignedProposal(&proposal.VersionedSignedProposal, 3)

	require.NoError(t, err)
	require.NotNil(t, psd.SignedData)
	require.Equal(t, 3, psd.ShareIdx)
}

func TestVersionedSignedProposal(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedSignedProposal
	}

	tests := []testCase{
		{
			name: "phase0",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   testutil.RandomPhase0BeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "altair",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   testutil.RandomAltairBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   testutil.RandomBellatrixBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionBellatrix,
				BellatrixBlinded: &eth2bellatrix.SignedBlindedBeaconBlock{
					Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "capella",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: &capella.SignedBeaconBlock{
					Message:   testutil.RandomCapellaBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "capella blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				CapellaBlinded: &eth2capella.SignedBlindedBeaconBlock{
					Message:   testutil.RandomCapellaBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "deneb",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   testutil.RandomDenebVersionedSignedProposal().Deneb,
			},
		},
		{
			name: "deneb blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				DenebBlinded: &eth2deneb.SignedBlindedBeaconBlock{
					Message:   testutil.RandomDenebBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := core.NewVersionedSignedProposal(&test.proposal)
			require.NoError(t, err)

			msgRoot, err := p.MessageRoot()
			require.NoError(t, err)
			require.NotEmpty(t, msgRoot)

			_, err = p.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)

			clone, err := p.Clone()
			require.NoError(t, err)
			require.Equal(t, p, clone)

			js, err := p.MarshalJSON()
			require.NoError(t, err)

			p2 := &core.VersionedSignedProposal{}
			err = p2.UnmarshalJSON(js)
			require.NoError(t, err)
			require.Equal(t, p, *p2)
		})
	}
}

func TestNewVersionedSignedBlindedProposal(t *testing.T) {
	type testCase struct {
		error    string
		proposal *eth2api.VersionedSignedBlindedProposal
	}

	tests := []testCase{
		{
			error: "unknown version",
			proposal: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersion(999),
			},
		},
		{
			error: "no bellatrix block",
			proposal: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionBellatrix,
			},
		},
		{
			error: "no capella block",
			proposal: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
			},
		},
		{
			error: "no deneb block",
			proposal: &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionDeneb,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.error, func(t *testing.T) {
			_, err := core.NewVersionedSignedBlindedProposal(test.proposal)
			require.ErrorContains(t, err, test.error)
		})
	}

	t.Run("happy path", func(t *testing.T) {
		proposal := testutil.RandomBellatrixVersionedSignedBlindedProposal()

		p, err := core.NewVersionedSignedBlindedProposal(&proposal.VersionedSignedBlindedProposal)
		require.NoError(t, err)
		require.Equal(t, proposal, p)
	})
}

func TestNewPartialVersionedSignedBlindedProposal(t *testing.T) {
	proposal := testutil.RandomBellatrixVersionedSignedBlindedProposal()

	psd, err := core.NewPartialVersionedSignedBlindedProposal(&proposal.VersionedSignedBlindedProposal, 3)

	require.NoError(t, err)
	require.NotNil(t, psd.SignedData)
	require.Equal(t, 3, psd.ShareIdx)
}

func TestVersionedSignedBlindedProposal(t *testing.T) {
	type testCase struct {
		name     string
		proposal eth2api.VersionedSignedBlindedProposal
	}

	tests := []testCase{
		{
			name:     "bellatrix",
			proposal: testutil.RandomBellatrixVersionedSignedBlindedProposal().VersionedSignedBlindedProposal,
		},
		{
			name:     "capella",
			proposal: testutil.RandomCapellaVersionedSignedBlindedProposal().VersionedSignedBlindedProposal,
		},
		{
			name:     "deneb",
			proposal: testutil.RandomDenebVersionedSignedBlindedProposal().VersionedSignedBlindedProposal,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := core.NewVersionedSignedBlindedProposal(&test.proposal)
			require.NoError(t, err)

			msgRoot, err := p.MessageRoot()
			require.NoError(t, err)
			require.NotEmpty(t, msgRoot)

			_, err = p.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)

			clone, err := p.Clone()
			require.NoError(t, err)
			require.Equal(t, p, clone)

			js, err := p.MarshalJSON()
			require.NoError(t, err)

			p2 := &core.VersionedSignedBlindedProposal{}
			err = p2.UnmarshalJSON(js)
			require.NoError(t, err)
			require.Equal(t, p, *p2)
		})
	}
}
