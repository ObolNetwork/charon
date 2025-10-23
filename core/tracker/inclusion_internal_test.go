// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"math/rand"
	"slices"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDuplicateAttData(t *testing.T) {
	ctx := context.Background()

	featureset.EnableForT(t, featureset.AttestationInclusion)

	tests := []struct {
		name                 string
		attData              *eth2p0.AttestationData
		attestationsFunc     func(*eth2p0.AttestationData, bitfield.Bitlist, bitfield.Bitlist, bitfield.Bitlist) []*eth2spec.VersionedAttestation
		beaconCommitteesFunc func(*eth2p0.AttestationData) []*eth2v1.BeaconCommittee
	}{
		{
			name:    "phase0",
			attData: testutil.RandomAttestationDataPhase0(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionPhase0, Phase0: &eth2p0.Attestation{AggregationBits: aggBits1, Data: attData}},
					{Version: eth2spec.DataVersionPhase0, Phase0: &eth2p0.Attestation{AggregationBits: aggBits2, Data: attData}},
					{Version: eth2spec.DataVersionPhase0, Phase0: &eth2p0.Attestation{AggregationBits: aggBits3, Data: attData}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: attData.Index, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1}},
				}
			},
		},
		{
			name:    "altair",
			attData: testutil.RandomAttestationDataPhase0(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionAltair, Altair: &eth2p0.Attestation{AggregationBits: aggBits1, Data: attData}},
					{Version: eth2spec.DataVersionAltair, Altair: &eth2p0.Attestation{AggregationBits: aggBits2, Data: attData}},
					{Version: eth2spec.DataVersionAltair, Altair: &eth2p0.Attestation{AggregationBits: aggBits3, Data: attData}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: attData.Index, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1}},
				}
			},
		},
		{
			name:    "bellatrix",
			attData: testutil.RandomAttestationDataPhase0(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionBellatrix, Bellatrix: &eth2p0.Attestation{AggregationBits: aggBits1, Data: attData}},
					{Version: eth2spec.DataVersionBellatrix, Bellatrix: &eth2p0.Attestation{AggregationBits: aggBits2, Data: attData}},
					{Version: eth2spec.DataVersionBellatrix, Bellatrix: &eth2p0.Attestation{AggregationBits: aggBits3, Data: attData}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: attData.Index, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1}},
				}
			},
		},
		{
			name:    "capella",
			attData: testutil.RandomAttestationDataPhase0(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionCapella, Capella: &eth2p0.Attestation{AggregationBits: aggBits1, Data: attData}},
					{Version: eth2spec.DataVersionCapella, Capella: &eth2p0.Attestation{AggregationBits: aggBits2, Data: attData}},
					{Version: eth2spec.DataVersionCapella, Capella: &eth2p0.Attestation{AggregationBits: aggBits3, Data: attData}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: attData.Index, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1}},
				}
			},
		},
		{
			name:    "deneb",
			attData: testutil.RandomAttestationDataPhase0(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: aggBits1, Data: attData}},
					{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: aggBits2, Data: attData}},
					{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: aggBits3, Data: attData}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: attData.Index, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1}},
				}
			},
		},
		{
			name:    "electra",
			attData: testutil.RandomAttestationDataElectra(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				zeroComm := bitfield.NewBitvector64()
				zeroComm.SetBitAt(0, true)

				oneComm := bitfield.NewBitvector64()
				oneComm.SetBitAt(1, true)

				twoComm := bitfield.NewBitvector64()
				twoComm.SetBitAt(2, true)

				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionElectra, Electra: &electra.Attestation{AggregationBits: aggBits1, Data: attData, CommitteeBits: zeroComm}},
					{Version: eth2spec.DataVersionElectra, Electra: &electra.Attestation{AggregationBits: aggBits2, Data: attData, CommitteeBits: oneComm}},
					{Version: eth2spec.DataVersionElectra, Electra: &electra.Attestation{AggregationBits: aggBits3, Data: attData, CommitteeBits: twoComm}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: 0, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 1, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 2, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
				}
			},
		},
		{
			name:    "electra - multiple committies per attestation",
			attData: testutil.RandomAttestationDataElectra(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				zeroTwoComm := bitfield.NewBitvector64()
				zeroTwoComm.SetBitAt(0, true)
				zeroTwoComm.SetBitAt(2, true)

				oneComm := bitfield.NewBitvector64()
				oneComm.SetBitAt(1, true)

				complexAttestationAggBits := slices.Concat(aggBits1, aggBits2)

				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionElectra, Electra: &electra.Attestation{AggregationBits: complexAttestationAggBits, Data: attData, CommitteeBits: zeroTwoComm}},
					{Version: eth2spec.DataVersionElectra, Electra: &electra.Attestation{AggregationBits: aggBits2, Data: attData, CommitteeBits: oneComm}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: 0, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 1, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 2, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
				}
			},
		},
		{
			name:    "fulu",
			attData: testutil.RandomAttestationDataElectra(),
			attestationsFunc: func(attData *eth2p0.AttestationData, aggBits1 bitfield.Bitlist, aggBits2 bitfield.Bitlist, aggBits3 bitfield.Bitlist) []*eth2spec.VersionedAttestation {
				zeroComm := bitfield.NewBitvector64()
				zeroComm.SetBitAt(0, true)

				oneComm := bitfield.NewBitvector64()
				oneComm.SetBitAt(1, true)

				twoComm := bitfield.NewBitvector64()
				twoComm.SetBitAt(2, true)

				return []*eth2spec.VersionedAttestation{
					{Version: eth2spec.DataVersionFulu, Fulu: &electra.Attestation{AggregationBits: aggBits1, Data: attData, CommitteeBits: zeroComm}},
					{Version: eth2spec.DataVersionFulu, Fulu: &electra.Attestation{AggregationBits: aggBits2, Data: attData, CommitteeBits: oneComm}},
					{Version: eth2spec.DataVersionFulu, Fulu: &electra.Attestation{AggregationBits: aggBits3, Data: attData, CommitteeBits: twoComm}},
				}
			},
			beaconCommitteesFunc: func(attData *eth2p0.AttestationData) []*eth2v1.BeaconCommittee {
				return []*eth2v1.BeaconCommittee{
					{Index: 0, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 1, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 2, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bmock, err := beaconmock.New(t.Context())
			require.NoError(t, err)

			// Mock 3 attestations, with same data but different aggregation bits.
			attData := test.attData
			aggBits1 := testutil.RandomBitList(8)
			aggBits2 := testutil.RandomBitList(8)
			aggBits3 := testutil.RandomBitList(8)

			bmock.BeaconBlockAttestationsFunc = func(_ context.Context, _ *eth2api.BeaconBlockAttestationsOpts) ([]*eth2spec.VersionedAttestation, error) {
				return test.attestationsFunc(attData, aggBits1, aggBits2, aggBits3), nil
			}

			bmock.BeaconCommitteesFunc = func(_ context.Context, opts *eth2api.BeaconCommitteesOpts) ([]*eth2v1.BeaconCommittee, error) {
				return test.beaconCommitteesFunc(attData), nil
			}

			noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

			incl, err := NewInclusion(ctx, bmock, noopTrackerInclFunc)
			require.NoError(t, err)

			done := make(chan struct{})
			attDataRoot, err := attData.HashTreeRoot()
			require.NoError(t, err)

			// Assert that the block to check contains all bitlists above.
			incl.checkBlockAndAttsFunc = func(ctx context.Context, block block) {
				require.Len(t, block.AttestationsByDataRoot, 1)
				att, ok := block.AttestationsByDataRoot[attDataRoot]
				require.True(t, ok)

				aggBits1, err := att.AggregationBits()
				require.NoError(t, err)
				ok, err = aggBits1.Contains(aggBits1)
				require.NoError(t, err)
				require.True(t, ok)

				aggBits2, err := att.AggregationBits()
				require.NoError(t, err)
				ok, err = aggBits2.Contains(aggBits2)
				require.NoError(t, err)
				require.True(t, ok)

				aggBits3, err := att.AggregationBits()
				require.NoError(t, err)
				ok, err = aggBits3.Contains(aggBits3)
				require.NoError(t, err)
				require.True(t, ok)

				close(done)
			}

			err = incl.checkBlock(ctx, uint64(attData.Slot), nil)
			require.NoError(t, err)

			<-done
		})
	}
}

func TestInclusion(t *testing.T) {
	featureset.EnableForT(t, featureset.AttestationInclusion)
	// Setup inclusion with a mock missedFunc and attIncludedFunc
	var missed, included []core.Duty

	incl := &inclusionCore{
		missedFunc: func(ctx context.Context, sub submission) {
			missed = append(missed, sub.Duty)
		},
		attIncludedFunc: func(ctx context.Context, sub submission, block block) {
			included = append(included, sub.Duty)
		},
		trackerInclFunc: func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {},
		submissions:     make(map[subkey]submission),
	}

	// Create some duties
	att1 := testutil.RandomDenebVersionedAttestation()
	att1Duty := core.NewAttesterDuty(uint64(att1.Deneb.Data.Slot))

	agg2 := testutil.RandomDenebVersionedSignedAggregateAndProof()
	agg2Duty := core.NewAggregatorDuty(uint64(agg2.Deneb.Message.Aggregate.Data.Slot))

	att3 := testutil.RandomPhase0Attestation()
	att3Duty := core.NewAttesterDuty(uint64(att3.Data.Slot))

	block4 := testutil.RandomDenebVersionedSignedProposal()
	block4Duty := core.NewProposerDuty(uint64(block4.Deneb.SignedBlock.Message.Slot))

	block5 := testutil.RandomDenebVersionedSignedBlindedProposal()
	block5.DenebBlinded.Message.Body.Graffiti = eth2wrap.GetSyntheticGraffiti() // Ignored, not included or missed.
	block5Duty := core.Duty{
		Slot: uint64(block5.DenebBlinded.Message.Slot),
		Type: core.DutyBuilderProposer,
	}

	// Submit all duties
	err := incl.Submitted(att1Duty, "", core.NewAttestation(att1.Deneb), 0)
	require.NoError(t, err)
	err = incl.Submitted(agg2Duty, "", core.NewSignedAggregateAndProof(agg2.Deneb), 0)
	require.NoError(t, err)
	err = incl.Submitted(att3Duty, "", core.NewAttestation(att3), 0)
	require.NoError(t, err)

	coreBlock4, err := core.NewVersionedSignedProposal(block4)
	require.NoError(t, err)
	err = incl.Submitted(block4Duty, "", coreBlock4, 0)
	require.NoError(t, err)
	err = incl.Submitted(block5Duty, "", block5, 0)
	require.NoError(t, err)

	// Create a mock block with the 1st and 2nd attestations.
	att1Root, err := att1.Deneb.Data.HashTreeRoot()
	require.NoError(t, err)
	att2Root, err := agg2.Deneb.Message.Aggregate.Data.HashTreeRoot()
	require.NoError(t, err)
	// Add some random aggregation bits to the attestation
	addRandomBits(att1.Deneb.AggregationBits)
	addRandomBits(agg2.Deneb.Message.Aggregate.AggregationBits)

	block := block{
		Slot: block4Duty.Slot,
		AttestationsByDataRoot: map[eth2p0.Root]*eth2spec.VersionedAttestation{
			att1Root: att1,
			att2Root: {Deneb: agg2.Deneb.Message.Aggregate},
		},
	}

	// Check the block
	incl.CheckBlockAndAtts(context.Background(), block)

	// Assert that the 1st and 2nd duty was included
	duties := []core.Duty{att1Duty, agg2Duty, att3Duty}
	require.ElementsMatch(t, included, duties)
}

func addRandomBits(list bitfield.Bitlist) {
	for range rand.Intn(4) {
		list.SetBitAt(uint64(rand.Intn(int(list.Len()))), true)
	}
}

func TestBlockInclusion(t *testing.T) {
	t.Run("block found", func(t *testing.T) {
		var missed []core.Duty

		incl := &inclusionCore{
			missedFunc: func(ctx context.Context, sub submission) {
				missed = append(missed, sub.Duty)
			},
			trackerInclFunc: func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {},
			submissions:     make(map[subkey]submission),
		}

		block := testutil.RandomFuluVersionedSignedProposal()
		blockSlot, err := block.Slot()
		require.NoError(t, err)

		blockDuty := core.NewProposerDuty(uint64(blockSlot))
		coreBlock, err := core.NewVersionedSignedProposal(block)
		require.NoError(t, err)
		err = incl.Submitted(blockDuty, "", coreBlock, 0)
		require.NoError(t, err)

		incl.CheckBlock(context.Background(), blockDuty.Slot, true)
		require.Empty(t, missed)
	})

	t.Run("block not found", func(t *testing.T) {
		var missed []core.Duty

		incl := &inclusionCore{
			missedFunc: func(ctx context.Context, sub submission) {
				missed = append(missed, sub.Duty)
			},
			trackerInclFunc: func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {},
			submissions:     make(map[subkey]submission),
		}

		block := testutil.RandomElectraVersionedSignedProposal()
		blockSlot, err := block.Slot()
		require.NoError(t, err)

		blockDuty := core.NewProposerDuty(uint64(blockSlot))
		coreBlock, err := core.NewVersionedSignedProposal(block)
		require.NoError(t, err)
		err = incl.Submitted(blockDuty, "", coreBlock, 0)
		require.NoError(t, err)

		incl.CheckBlock(context.Background(), blockDuty.Slot, false)
		require.Len(t, missed, 1)
	})

	t.Run("received block not found in submissions", func(t *testing.T) {
		var missed []core.Duty

		incl := &inclusionCore{
			missedFunc: func(ctx context.Context, sub submission) {
				missed = append(missed, sub.Duty)
			},
			trackerInclFunc: func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {},
			submissions:     make(map[subkey]submission),
		}

		block := testutil.RandomFuluVersionedSignedProposal()
		blockSlot, err := block.Slot()
		require.NoError(t, err)

		blockDuty := core.NewProposerDuty(uint64(blockSlot))
		coreBlock, err := core.NewVersionedSignedProposal(block)
		require.NoError(t, err)
		err = incl.Submitted(blockDuty, "", coreBlock, 0)
		require.NoError(t, err)

		incl.CheckBlock(context.Background(), blockDuty.Slot+1, true)
		require.Empty(t, missed)
	})

	t.Run("received block is nil and not found in submissions", func(t *testing.T) {
		var missed []core.Duty

		incl := &inclusionCore{
			missedFunc: func(ctx context.Context, sub submission) {
				missed = append(missed, sub.Duty)
			},
			trackerInclFunc: func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {},
			submissions:     make(map[subkey]submission),
		}

		block := testutil.RandomFuluVersionedSignedProposal()
		blockSlot, err := block.Slot()
		require.NoError(t, err)

		blockDuty := core.NewProposerDuty(uint64(blockSlot))
		coreBlock, err := core.NewVersionedSignedProposal(block)
		require.NoError(t, err)
		err = incl.Submitted(blockDuty, "", coreBlock, 0)
		require.NoError(t, err)

		incl.CheckBlock(context.Background(), blockDuty.Slot+1, false)
		require.Empty(t, missed)
	})
}

func TestInclusion404Handling(t *testing.T) {
	ctx := context.Background()

	t.Run("checkBlock handles 404 error gracefully", func(t *testing.T) {
		bmock, err := beaconmock.New(ctx)
		require.NoError(t, err)

		// Mock SignedBeaconBlock to return a 404 error
		bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
			return nil, &eth2api.Error{
				StatusCode: 404,
				Method:     "GET",
				Endpoint:   "/eth/v2/beacon/blocks/" + blockID,
				Data:       []byte(`{"code":404,"message":"NOT_FOUND: beacon block not found"}`),
			}
		}

		// Wrap beaconmock with eth2wrap to get proper error handling
		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
		require.NoError(t, err)

		var (
			checkBlockCalled bool
			foundBlock       bool
		)

		noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

		incl, err := NewInclusion(ctx, eth2Cl, noopTrackerInclFunc)
		require.NoError(t, err)

		// Override checkBlockFunc to capture the result
		incl.checkBlockFunc = func(ctx context.Context, slot uint64, found bool) {
			checkBlockCalled = true
			foundBlock = found
		}

		// Call checkBlock with a slot that will trigger the 404
		err = incl.checkBlock(ctx, 12345, nil)
		require.NoError(t, err, "checkBlock should not return an error for 404")
		require.True(t, checkBlockCalled, "checkBlockFunc should have been called")
		require.False(t, foundBlock, "block should be marked as not found")
	})

	t.Run("checkBlockAndAtts handles 404 error gracefully", func(t *testing.T) {
		featureset.EnableForT(t, featureset.AttestationInclusion)

		bmock, err := beaconmock.New(ctx)
		require.NoError(t, err)

		// Mock BeaconBlockAttestations to return a 404 error
		bmock.BeaconBlockAttestationsFunc = func(ctx context.Context, opts *eth2api.BeaconBlockAttestationsOpts) ([]*eth2spec.VersionedAttestation, error) {
			return nil, &eth2api.Error{
				StatusCode: 404,
				Method:     "GET",
				Endpoint:   "/eth/v1/beacon/blocks/" + opts.Block + "/attestations",
				Data:       []byte(`{"code":404,"message":"NOT_FOUND: beacon block not found"}`),
			}
		}

		// Wrap beaconmock with eth2wrap to get proper error handling
		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
		require.NoError(t, err)

		noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

		incl, err := NewInclusion(ctx, eth2Cl, noopTrackerInclFunc)
		require.NoError(t, err)

		// Call checkBlockAndAtts with a slot that will trigger the 404
		err = incl.checkBlockAndAtts(ctx, 12345, nil)
		require.NoError(t, err, "checkBlockAndAtts should not return an error for 404")
	})

	t.Run("checkBlock returns error for non-404 errors", func(t *testing.T) {
		bmock, err := beaconmock.New(ctx)
		require.NoError(t, err)

		// Mock SignedBeaconBlock to return a 500 error
		bmock.SignedBeaconBlockFunc = func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
			return nil, &eth2api.Error{
				StatusCode: 500,
				Method:     "GET",
				Endpoint:   "/eth/v2/beacon/blocks/" + blockID,
				Data:       []byte(`{"code":500,"message":"Internal server error"}`),
			}
		}

		// Wrap beaconmock with eth2wrap to get proper error handling
		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
		require.NoError(t, err)

		noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

		incl, err := NewInclusion(ctx, eth2Cl, noopTrackerInclFunc)
		require.NoError(t, err)

		// Call checkBlock with a slot that will trigger the 500 error
		err = incl.checkBlock(ctx, 12345, nil)
		require.Error(t, err, "checkBlock should return an error for non-404 errors")
	})

	t.Run("checkBlockAndAtts returns error for non-404 errors", func(t *testing.T) {
		featureset.EnableForT(t, featureset.AttestationInclusion)

		bmock, err := beaconmock.New(ctx)
		require.NoError(t, err)

		// Mock BeaconBlockAttestations to return a 500 error
		bmock.BeaconBlockAttestationsFunc = func(ctx context.Context, opts *eth2api.BeaconBlockAttestationsOpts) ([]*eth2spec.VersionedAttestation, error) {
			return nil, &eth2api.Error{
				StatusCode: 500,
				Method:     "GET",
				Endpoint:   "/eth/v1/beacon/blocks/" + opts.Block + "/attestations",
				Data:       []byte(`{"code":500,"message":"Internal server error"}`),
			}
		}

		// Wrap beaconmock with eth2wrap to get proper error handling
		eth2Cl, err := eth2wrap.Instrument([]eth2wrap.Client{bmock}, nil)
		require.NoError(t, err)

		noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

		incl, err := NewInclusion(ctx, eth2Cl, noopTrackerInclFunc)
		require.NoError(t, err)

		// Call checkBlockAndAtts with a slot that will trigger the 500 error
		err = incl.checkBlockAndAtts(ctx, 12345, nil)
		require.Error(t, err, "checkBlockAndAtts should return an error for non-404 errors")
	})
}
