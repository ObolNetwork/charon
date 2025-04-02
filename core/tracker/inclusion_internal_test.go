// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"math/rand"
	"slices"
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/statecomm"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDuplicateAttData(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                      string
		attData                   *eth2p0.AttestationData
		attestationsFunc          func(*eth2p0.AttestationData, bitfield.Bitlist, bitfield.Bitlist, bitfield.Bitlist) []*eth2spec.VersionedAttestation
		beaconStateCommitteesFunc func(*eth2p0.AttestationData) []*statecomm.StateCommittee
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
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
			beaconStateCommitteesFunc: func(attData *eth2p0.AttestationData) []*statecomm.StateCommittee {
				return []*statecomm.StateCommittee{
					{Index: 0, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 1, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
					{Index: 2, Slot: attData.Slot, Validators: []eth2p0.ValidatorIndex{0, 1, 2}},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bmock, err := beaconmock.New()
			require.NoError(t, err)

			// Mock 3 attestations, with same data but different aggregation bits.
			attData := test.attData
			aggBits1 := testutil.RandomBitList(8)
			aggBits2 := testutil.RandomBitList(8)
			aggBits3 := testutil.RandomBitList(8)

			bmock.BlockAttestationsV2Func = func(_ context.Context, _ string) ([]*eth2spec.VersionedAttestation, error) {
				return test.attestationsFunc(attData, aggBits1, aggBits2, aggBits3), nil
			}

			bmock.BeaconStateCommitteesFunc = func(_ context.Context, slot uint64) ([]*statecomm.StateCommittee, error) {
				return test.beaconStateCommitteesFunc(attData), nil
			}

			noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

			incl, err := NewInclusion(ctx, bmock, noopTrackerInclFunc)
			require.NoError(t, err)

			done := make(chan struct{})
			attDataRoot, err := attData.HashTreeRoot()
			require.NoError(t, err)

			// Assert that the block to check contains all bitlists above.
			incl.checkBlockV2Func = func(ctx context.Context, block blockV2) {
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

			err = incl.checkBlock(ctx, uint64(attData.Slot))
			require.NoError(t, err)

			<-done
		})
	}
}

func TestInclusion(t *testing.T) {
	//  Setup inclusion with a mock missedFunc and attIncludedFunc
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
	att1 := testutil.RandomPhase0Attestation()
	att1Duty := core.NewAttesterDuty(uint64(att1.Data.Slot))

	agg2 := testutil.RandomSignedAggregateAndProof()
	agg2Duty := core.NewAggregatorDuty(uint64(agg2.Message.Aggregate.Data.Slot))

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
	err := incl.Submitted(att1Duty, "", core.NewAttestation(att1), 0)
	require.NoError(t, err)
	err = incl.Submitted(agg2Duty, "", core.NewSignedAggregateAndProof(agg2), 0)
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
	att1Root, err := att1.Data.HashTreeRoot()
	require.NoError(t, err)
	att2Root, err := agg2.Message.Aggregate.Data.HashTreeRoot()
	require.NoError(t, err)
	// Add some random aggregation bits to the attestation
	addRandomBits(att1.AggregationBits)
	addRandomBits(agg2.Message.Aggregate.AggregationBits)

	block := block{
		Slot: block4Duty.Slot,
		AttestationsByDataRoot: map[eth2p0.Root]*eth2p0.Attestation{
			att1Root: att1,
			att2Root: agg2.Message.Aggregate,
		},
	}

	// Check the block
	incl.CheckBlock(context.Background(), block)

	// Assert that the 1st and 2nd duty was included
	duties := []core.Duty{att1Duty, agg2Duty}
	require.ElementsMatch(t, included, duties)

	// Trim the duties
	incl.Trim(context.Background(), att3Duty.Slot)
	// Assert that the 3rd duty was missed
	require.Equal(t, []core.Duty{att3Duty}, missed)
}

func addRandomBits(list bitfield.Bitlist) {
	for range rand.Intn(4) {
		list.SetBitAt(uint64(rand.Intn(int(list.Len()))), true)
	}
}
