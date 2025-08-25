// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"encoding/json"
	"fmt"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// To satisfy linter.
const unmarshalPrefix = "unmarshal "

func TestSignedDataSetSignature(t *testing.T) {
	tests := []struct {
		name string
		data core.SignedData
	}{
		{
			name: "versioned signed proposal phase0",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionPhase0,
					Phase0: &eth2p0.SignedBeaconBlock{
						Message:   testutil.RandomPhase0BeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed proposal altair",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionAltair,
					Altair: &altair.SignedBeaconBlock{
						Message:   testutil.RandomAltairBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed proposal bellatrix",
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
			name: "versioned signed proposal bellatrix blinded",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionBellatrix,
					BellatrixBlinded: &eth2bellatrix.SignedBlindedBeaconBlock{
						Message:   testutil.RandomBellatrixBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
					Blinded: true,
				},
			},
		},
		{
			name: "versioned signed proposal capella",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionCapella,
					Capella: &capella.SignedBeaconBlock{
						Message:   testutil.RandomCapellaBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "versioned signed proposal capella blinded",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionCapella,
					CapellaBlinded: &eth2capella.SignedBlindedBeaconBlock{
						Message:   testutil.RandomCapellaBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
					Blinded: true,
				},
			},
		},
		{
			name: "versioned signed proposal deneb",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2deneb.SignedBlockContents{
						SignedBlock: &deneb.SignedBeaconBlock{
							Message:   testutil.RandomDenebBeaconBlock(),
							Signature: testutil.RandomEth2Signature(),
						},
						KZGProofs: []deneb.KZGProof{},
						Blobs:     []deneb.Blob{},
					},
				},
			},
		},
		{
			name: "versioned signed proposal deneb blinded",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionDeneb,
					DenebBlinded: &eth2deneb.SignedBlindedBeaconBlock{
						Message:   testutil.RandomDenebBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
					Blinded: true,
				},
			},
		},
		{
			name: "versioned signed proposal electra",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionElectra,
					Electra: &eth2electra.SignedBlockContents{
						SignedBlock: &electra.SignedBeaconBlock{
							Message:   testutil.RandomElectraBeaconBlock(),
							Signature: testutil.RandomEth2Signature(),
						},
						KZGProofs: []deneb.KZGProof{},
						Blobs:     []deneb.Blob{},
					},
				},
			},
		},
		{
			name: "versioned signed proposal electra blinded",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionElectra,
					ElectraBlinded: &eth2electra.SignedBlindedBeaconBlock{
						Message:   testutil.RandomElectraBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
					Blinded: true,
				},
			},
		},
		{
			name: "versioned signed proposal fulu",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionFulu,
					Fulu: &eth2electra.SignedBlockContents{
						SignedBlock: &electra.SignedBeaconBlock{
							Message:   testutil.RandomElectraBeaconBlock(),
							Signature: testutil.RandomEth2Signature(),
						},
						KZGProofs: []deneb.KZGProof{},
						Blobs:     []deneb.Blob{},
					},
				},
			},
		},
		{
			name: "versioned signed proposal fulu blinded",
			data: core.VersionedSignedProposal{
				VersionedSignedProposal: eth2api.VersionedSignedProposal{
					Version: eth2spec.DataVersionFulu,
					FuluBlinded: &eth2electra.SignedBlindedBeaconBlock{
						Message:   testutil.RandomElectraBlindedBeaconBlock(),
						Signature: testutil.RandomEth2Signature(),
					},
					Blinded: true,
				},
			},
		},
		{
			name: "signed beacon committee selection",
			data: testutil.RandomCoreBeaconCommitteeSelection(),
		},
		{
			name: "signed aggregate and proof phase0",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionPhase0,
					Phase0: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomPhase0Attestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof altair",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionAltair,
					Altair: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomPhase0Attestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof bellatrix",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomPhase0Attestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof capella",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomPhase0Attestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof deneb",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomPhase0Attestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof electra",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionElectra,
					Electra: &electra.SignedAggregateAndProof{
						Message: &electra.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomElectraAttestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed aggregate and proof fulu",
			data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionFulu,
					Fulu: &electra.SignedAggregateAndProof{
						Message: &electra.AggregateAndProof{
							AggregatorIndex: 0,
							Aggregate:       testutil.RandomElectraAttestation(),
							SelectionProof:  testutil.RandomEth2Signature(),
						},
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation phase0",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionPhase0,
					Phase0: &eth2p0.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation altair",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionAltair,
					Altair: &eth2p0.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation bellatrix",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &eth2p0.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation capella",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2p0.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation deneb",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2p0.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			name: "signed attestation electra",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionElectra,
					Electra: &electra.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
						CommitteeBits:   testutil.RandomBitVec64(),
					},
				},
			},
		},
		{
			name: "signed attestation fulu",
			data: core.VersionedAttestation{
				VersionedAttestation: eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionFulu,
					Fulu: &electra.Attestation{
						AggregationBits: testutil.RandomBitList(1),
						Data:            testutil.RandomAttestationDataPhase0(),
						Signature:       testutil.RandomEth2Signature(),
						CommitteeBits:   testutil.RandomBitVec64(),
					},
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
			error:   "no electra proposal",
			version: eth2spec.DataVersionElectra,
		},
		{
			error:   "no fulu proposal",
			version: eth2spec.DataVersionFulu,
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
		{
			error:   "no electra blinded proposal",
			version: eth2spec.DataVersionElectra,
			blinded: true,
		},
		{
			error:   "no fulu blinded proposal",
			version: eth2spec.DataVersionFulu,
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

func TestNewVersionedSignedProposalFromBlindedProposalElectra(t *testing.T) {
	proposal, err := testutil.RandomElectraVersionedSignedBlindedProposal().ToBlinded()
	require.NoError(t, err)

	pvsp, err := core.NewVersionedSignedProposalFromBlindedProposal(&proposal)

	require.NoError(t, err)
	require.NotNil(t, pvsp.ElectraBlinded)
}

func TestNewPartialVersionedSignedBlindedProposalElectra(t *testing.T) {
	proposal, err := testutil.RandomElectraVersionedSignedBlindedProposal().ToBlinded()
	require.NoError(t, err)

	pvsp, err := core.NewPartialVersionedSignedBlindedProposal(&proposal, 3)

	require.NoError(t, err)
	require.NotNil(t, pvsp.SignedData)
	require.Equal(t, 3, pvsp.ShareIdx)
}

func TestNewVersionedSignedProposalFromBlindedProposalFulu(t *testing.T) {
	proposal, err := testutil.RandomFuluVersionedSignedBlindedProposal().ToBlinded()
	require.NoError(t, err)

	pvsp, err := core.NewVersionedSignedProposalFromBlindedProposal(&proposal)

	require.NoError(t, err)
	require.NotNil(t, pvsp.FuluBlinded)
}

func TestNewPartialVersionedSignedBlindedProposalFulu(t *testing.T) {
	proposal, err := testutil.RandomFuluVersionedSignedBlindedProposal().ToBlinded()
	require.NoError(t, err)

	pvsp, err := core.NewPartialVersionedSignedBlindedProposal(&proposal, 3)

	require.NoError(t, err)
	require.NotNil(t, pvsp.SignedData)
	require.Equal(t, 3, pvsp.ShareIdx)
}

func TestNewVersionedAttestation(t *testing.T) {
	type testCase struct {
		error   string
		version eth2spec.DataVersion
	}

	tests := []testCase{
		{
			error:   "unknown version",
			version: eth2spec.DataVersion(999),
		},
		{
			error:   "no phase0 attestation",
			version: eth2spec.DataVersionPhase0,
		},
		{
			error:   "no altair attestation",
			version: eth2spec.DataVersionAltair,
		},
		{
			error:   "no bellatrix attestation",
			version: eth2spec.DataVersionBellatrix,
		},
		{
			error:   "no capella attestation",
			version: eth2spec.DataVersionCapella,
		},
		{
			error:   "no deneb attestation",
			version: eth2spec.DataVersionDeneb,
		},
		{
			error:   "no electra attestation",
			version: eth2spec.DataVersionElectra,
		},
		{
			error:   "no fulu attestation",
			version: eth2spec.DataVersionFulu,
		},
	}

	for _, test := range tests {
		t.Run(test.error, func(t *testing.T) {
			_, err := core.NewVersionedAttestation(&eth2spec.VersionedAttestation{
				Version: test.version,
			})
			require.ErrorContains(t, err, test.error)
		})
	}

	t.Run("happy path electra", func(t *testing.T) {
		attestation := testutil.RandomElectraCoreVersionedAttestation()

		p, err := core.NewVersionedAttestation(&attestation.VersionedAttestation)
		require.NoError(t, err)
		require.Equal(t, attestation, p)
	})

	t.Run("happy path fulu", func(t *testing.T) {
		attestation := testutil.RandomFuluCoreVersionedAttestation()

		p, err := core.NewVersionedAttestation(&attestation.VersionedAttestation)
		require.NoError(t, err)
		require.Equal(t, attestation, p)
	})
}

func TestNewPartialVersionedAttestationElectra(t *testing.T) {
	attestation := testutil.RandomElectraVersionedAttestation()

	pva, err := core.NewPartialVersionedAttestation(attestation, 3)

	require.NoError(t, err)
	require.NotNil(t, pva.SignedData)
	require.Equal(t, 3, pva.ShareIdx)
}

func TestNewPartialVersionedAttestationFulu(t *testing.T) {
	attestation := testutil.RandomFuluVersionedAttestation()

	pva, err := core.NewPartialVersionedAttestation(attestation, 3)

	require.NoError(t, err)
	require.NotNil(t, pva.SignedData)
	require.Equal(t, 3, pva.ShareIdx)
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
		{
			name: "electra",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionElectra,
				Electra: testutil.RandomElectraVersionedSignedProposal().Electra,
			},
		},
		{
			name: "electra blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionElectra,
				ElectraBlinded: &eth2electra.SignedBlindedBeaconBlock{
					Message:   testutil.RandomElectraBlindedBeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
				Blinded: true,
			},
		},
		{
			name: "fulu",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionFulu,
				Fulu:    testutil.RandomFuluVersionedSignedProposal().Fulu,
			},
		},
		{
			name: "fulu blinded",
			proposal: eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionFulu,
				FuluBlinded: &eth2electra.SignedBlindedBeaconBlock{
					Message:   testutil.RandomElectraBlindedBeaconBlock(),
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

			// Malformed data
			err = p2.UnmarshalJSON([]byte("malformed"))
			require.ErrorContains(t, err, "unmarshal block")

			if test.proposal.Version != eth2spec.DataVersionUnknown {
				js := fmt.Sprintf(`{"version":%d,"blinded":%v,"block":123}`, test.proposal.Version-1, test.proposal.Blinded)
				err = p2.UnmarshalJSON([]byte(js))
				require.ErrorContains(t, err, unmarshalPrefix+test.proposal.Version.String())
			}
		})
	}
}

func TestVersionedSignedAggregateAndProofUtilFunctions(t *testing.T) {
	data := testutil.RandomAttestationDataPhase0()
	aggregationBits := testutil.RandomBitList(64)

	type testCase struct {
		name              string
		aggregateAndProof core.VersionedSignedAggregateAndProof
	}

	tests := []testCase{
		{
			name: "phase0",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionPhase0,
					Phase0: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &eth2p0.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "altair",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionAltair,
					Altair: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &eth2p0.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "bellatrix",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionBellatrix,
					Bellatrix: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &eth2p0.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "capella",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionCapella,
					Capella: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &eth2p0.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "deneb",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2p0.SignedAggregateAndProof{
						Message: &eth2p0.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &eth2p0.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "electra",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionElectra,
					Electra: &electra.SignedAggregateAndProof{
						Message: &electra.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &electra.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
								CommitteeBits:   testutil.RandomBitVec64(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
		{
			name: "fulu",
			aggregateAndProof: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionFulu,
					Fulu: &electra.SignedAggregateAndProof{
						Message: &electra.AggregateAndProof{
							AggregatorIndex: testutil.RandomVIdx(),
							Aggregate: &electra.Attestation{
								AggregationBits: aggregationBits,
								Data:            data,
								Signature:       testutil.RandomEth2Signature(),
								CommitteeBits:   testutil.RandomBitVec64(),
							},
							SelectionProof: testutil.RandomEth2Signature(),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, data, test.aggregateAndProof.Data())
			require.Equal(t, aggregationBits, test.aggregateAndProof.AggregationBits())
		})
	}
}

// func TestGnosisProposals(t *testing.T) {
// 	baseProposal := eth2api.VersionedSignedProposal{
// 		Version: eth2spec.DataVersionDeneb,
// 		Deneb:   testutil.RandomDenebVersionedSignedProposal().Deneb,
// 	}

// 	rawGnosisProposal, err := core.NewVersionedSignedProposal(&baseProposal)
// 	require.NoError(t, err)

// 	rawStdProposal, err := core.NewVersionedSignedProposal(&baseProposal)
// 	require.NoError(t, err)

// 	featureset.EnableForT(t, featureset.GnosisBlockHotfix)

// 	gnosisProp := core.ParSignedData{
// 		SignedData: rawGnosisProposal,
// 		ShareIdx:   42,
// 	}

// 	gnosisRoot, err := gnosisProp.MessageRoot()
// 	require.NoError(t, err)

// 	featureset.DisableForT(t, featureset.GnosisBlockHotfix)

// 	stdProp := core.ParSignedData{
// 		SignedData: rawStdProposal,
// 		ShareIdx:   42,
// 	}

// 	stdRoot, err := stdProp.MessageRoot()
// 	require.NoError(t, err)

// 	require.NotEqual(t, stdRoot, gnosisRoot)
// }

// func TestGnosisRealBlockHash(t *testing.T) {
// 	const (
// 		realSszStr            = "f476b10000000000dc1c000000000000414c00276374153218243eba1b9c92821d64a83b1b7c5dd3f7c051f7b404e873079d1b1a97f18a191fbdf457f809e958473aed36593981bd990b9ba0103775425400000090a2e40b2745cdbcc797856161cebc85ca517f2c956a28682b4539fc1bd051355b39836bb73502fefe3c9683b6a899c802e3511378915c06dfb4cb5b218261ddc8abe0e5e4b7701272b7cdfb525764f580ad561ead7964bc40c188a609ea40458e289cb0e746320595ef0b1a6f1118b4949f016818c1457beb0d90f3ca06ff55cf05000000000000fc6c3b6e91805bfd2a224716830ab1644c4fdcfaad82aad5a4ac3d0ad33d6d20636861726f6e2f76312e312e302d6465762d38306635613236000000000000008801000088010000880100008805000088050000fffbbffffffff7ffff7ffe7ffffffef6ffffbfbfffeffffbddfffffffffff7ffff9ffffffbfffdffffefffffdfffffbfffbffdfffffdffffafffdffffdfff7bf98cca8f4c0aed716d5f6352e2e4adf58d398d132fadf9352abe53971b8dceba4a7c3ba29e176a4bfd9154736f370e83404bb55af4be453f72c066cbc05e882e29caebc707a0c38573d15c2e0c94e9f65f5c71743a4f24b683a9c5843e06aa2c988050000bc0c0000bc0c0000100000000c0100000802000004030000e4000000f376b100000000000100000000000000414c00276374153218243eba1b9c92821d64a83b1b7c5dd3f7c051f7b404e8736e170b0000000000aad68b53dc54fb14d6ae23decfd7b80b026e044d98f7537eb7a7a599e289d4c96f170b00000000004b57e3fcb8a9098573721e35021ccf5a03a52e5b6d0df29c6410ac3179d98198864379f3d48d26b4567bda0b95be3d4fb4977dc83bb360f117b64c8792ae82697690c5a8e4f66dbff6ea87ef089f9ee000a94c948d638228eb02acbd360bd0018b000496dabd4a0eb6af94a2700b1195d9bbb9c94aa6947a2cd13f7e460b15b7ffffffffffffffffdffeffffffefeffffffcffffffffff03e4000000f376b100000000000000000000000000414c00276374153218243eba1b9c92821d64a83b1b7c5dd3f7c051f7b404e8736e170b0000000000aad68b53dc54fb14d6ae23decfd7b80b026e044d98f7537eb7a7a599e289d4c96f170b00000000004b57e3fcb8a9098573721e35021ccf5a03a52e5b6d0df29c6410ac3179d98198a8823ae587250ebb681e5041b0e98177da564588e681fc9f03413dede12cb736edb0894d92d8acd453610a44faef61820884f08b95825263b6eb85ae3a1a9b7e372f24886f14f51f960a8ed7701621bc391518a771d82479159600dcf5fb472effffffffdffffffffeffffffffbdffffbf7fffffdfffff01e4000000f176b1000000000001000000000000002ab5a55abbffb1d54156aedc8f532ddc8e20b52ad418d274976c84bed8c6dfb96e170b0000000000aad68b53dc54fb14d6ae23decfd7b80b026e044d98f7537eb7a7a599e289d4c96f170b00000000004b57e3fcb8a9098573721e35021ccf5a03a52e5b6d0df29c6410ac3179d9819892abafc310b9960acd95315361d9fbf7d6dcace2525f614ac6202d34e09639b5fa654a80ad33cf1587faac32ee8799870475e38f3f34a7e8916692f2957c3bdc02e29b00c3bc236a690677165f015435f4995aa3fc24e8d4d757b6b410a694c3000000000000000000000000000000000000000000001002e4000000f176b1000000000000000000000000002ab5a55abbffb1d54156aedc8f532ddc8e20b52ad418d274976c84bed8c6dfb96e170b0000000000aad68b53dc54fb14d6ae23decfd7b80b026e044d98f7537eb7a7a599e289d4c96f170b00000000004b57e3fcb8a9098573721e35021ccf5a03a52e5b6d0df29c6410ac3179d981988accfe8cd3246977e00443e4096ee201b57f3ebc03df78ce067ef40a994baf40f020ffb197c339773f807cddea4f9c51036909facf3fcf763998ae703c8c70aacc6519948bd20283800f199b08ff6005b6c4ec096bd3aef1cb93efc17f0724b4000000000000000000000000000000000000000004000001b1b6d67608054e32ca56184f8bf612f9c0e8df9f99fc7607ff1fe865e80f04317ce7390c41ce3416c4a0a297761c71763d89ca3baa3f345a5c48d0e9470c650b41e38dfdae05db0df098fae94a61cd1fca5b6fdac426de6f735cfb1799cbc9729fa60a19de90b88201b1ba442cc5624a17f6a3590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026f600f4172341b485e1fb406f5334b3d4887d896ca54fd71ba2590c752574ef3905ac000000000062690401000000003ddd0100000000001041bb66000000001002000007000000000000000000000000000000000000000000000000000000000000008eb2a7234864cd0d17fe81e4c229130ee883dce5b577801526e355d4a44a397b1a020000d4050000000000000000000000000000000000004e65746865726d696e6408000000e101000002f901d58227d8825e9784b2d05e0084b2d05e00831632a8948448e15d0e706c0298deca99f0b4744030e59d7d80b90164e7a2c01f00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000118000500000735a05d7e98453b1abcedec7918072d3d6f5ec20000000000000d3ec6755144d60548f3dd420f47cf48dae553bbf0423f5929bee6a59661d6ccc9c4eb751048009ce11b0007a120030200aa36a727d869f5590300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000187290cd402054b514751d3cfb037c8ee0eda175f7c6b19c0b0dd529dff22054800000000000000000000000000000000000000000000000000000000000000012cda73507147b818a330a53afea6536c40ea9fb3e20107a1147fdb1e798417d90000000000000000c001a019a3a3e71b2e3418e753bbee132a4dbfebf6fe54c09a5efafcaafd48a797f2e6a044d24ef0e9d489da2f1cf5969a2a639506f133e8a35dc7b546fe84977c6473a202f901d58227d8825e9884b2d05e0084b2d05e00831632a8948448e15d0e706c0298deca99f0b4744030e59d7d80b90164e7a2c01f00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000118000500000735a05d7e98453b1abcedec7918072d3d6f5ec20000000000000d54c6755144d60548f3dd420f47cf48dae553bbf0423f5929bee6a59661d6ccc9c4eb751048009ce11b0007a120030200aa36a727d869f55903000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001ca21552ef9a14f965d7fd033812e635db7b1f5d5a25f42d5749d804653ac80dd0000000000000000000000000000000000000000000000000000000000000001bc4cd07038c77b7e752abf26ceaa64d2d9c71d05b6436a95bc2b3f5a2173eb920000000000000000c001a075bd587dcc1b039a8ad587050af69ec56714a570d7cb90f1de673cff7d2f2151a0540002cf0799372453b7d752fe235bd5d83c30cf8fdb8eb3fefd5060e093b2825e27050300000000960f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5173f50e00000000005f27050300000000970f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5196470f00000000006027050300000000980f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df5196470f00000000006127050300000000990f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51b01b0f000000000062270503000000009a0f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51d4293c000000000063270503000000009b0f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51f51e0f000000000064270503000000009d0f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51b6f20e000000000065270503000000009e0f000000000000cc4e00a72d871d6c328bcfe9025ad93d0a26df51a283150000000000"
// 		expectedGnosisHashStr = "9ddaf2f91ad6b426603286c98aa71a659b13475c4e71c9b5603b86528a072137"
// 		expectedStdHashStr    = "bdf303daf3b3f1735460c0ee0de2646a39247daadf091d3cfc7f7cb70c696426"
// 	)
// 	realSsz, err := hex.DecodeString(realSszStr)
// 	require.NoError(t, err)

// 	m := &deneb.GnosisBeaconBlock{}
// 	err = m.UnmarshalSSZ(realSsz)
// 	require.NoError(t, err)

// 	realHash, err := m.HashTreeRoot()
// 	require.NoError(t, err)
// 	require.Equal(t, expectedGnosisHashStr, hex.EncodeToString(realHash[:]))

// 	mStd := &deneb.BeaconBlock{}
// 	err = mStd.UnmarshalSSZ(realSsz)
// 	require.NoError(t, err)

// 	realHashStd, err := mStd.HashTreeRoot()
// 	require.NoError(t, err)
// 	require.Equal(t, expectedStdHashStr, hex.EncodeToString(realHashStd[:]))
// }
