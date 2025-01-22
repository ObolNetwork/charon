// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"math/rand"
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestDuplicateAttData(t *testing.T) {
	ctx := context.Background()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Mock 3 attestations, with same data but different aggregation bits.
	bits1 := testutil.RandomBitList(8)
	bits2 := testutil.RandomBitList(8)
	bits3 := testutil.RandomBitList(8)
	attData := testutil.RandomAttestationData()

	bmock.BlockAttestationsV2Func = func(_ context.Context, _ string) ([]*eth2spec.VersionedAttestation, error) {
		return []*eth2spec.VersionedAttestation{
			{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: bits1, Data: attData}},
			{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: bits2, Data: attData}},
			{Version: eth2spec.DataVersionDeneb, Deneb: &eth2p0.Attestation{AggregationBits: bits3, Data: attData}},
		}, nil
	}

	noopTrackerInclFunc := func(duty core.Duty, key core.PubKey, data core.SignedData, err error) {}

	incl, err := NewInclusion(ctx, bmock, noopTrackerInclFunc)
	require.NoError(t, err)

	done := make(chan struct{})
	attDataRoot, err := attData.HashTreeRoot()
	require.NoError(t, err)

	// Assert that the block to check contains all bitlists above.
	incl.checkBlockFunc = func(ctx context.Context, block block) {
		require.Len(t, block.AttestationsByDataRoot, 1)
		att, ok := block.AttestationsByDataRoot[attDataRoot]
		require.True(t, ok)

		ok, err := att.Deneb.AggregationBits.Contains(bits1)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = att.Deneb.AggregationBits.Contains(bits2)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = att.Deneb.AggregationBits.Contains(bits3)
		require.NoError(t, err)
		require.True(t, ok)

		close(done)
	}

	err = incl.checkBlock(ctx, uint64(attData.Slot))
	require.NoError(t, err)

	<-done
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
	att1 := testutil.RandomDenebVersionedAttestation()
	att1Data, err := att1.Data()
	require.NoError(t, err)
	att1Duty := core.NewAttesterDuty(uint64(att1Data.Slot))

	agg2 := testutil.RandomSignedAggregateAndProof()
	slot, err := agg2.Slot()
	require.NoError(t, err)
	agg2Duty := core.NewAggregatorDuty(uint64(slot))

	att3 := testutil.RandomDenebVersionedAttestation()
	att3Data, err := att3.Data()
	require.NoError(t, err)
	att3Duty := core.NewAttesterDuty(uint64(att3Data.Slot))

	block4 := testutil.RandomDenebVersionedSignedProposal()
	block4Duty := core.NewProposerDuty(uint64(block4.Deneb.SignedBlock.Message.Slot))

	block5 := testutil.RandomDenebVersionedSignedBlindedProposal()
	block5.DenebBlinded.Message.Body.Graffiti = eth2wrap.GetSyntheticGraffiti() // Ignored, not included or missed.
	block5Duty := core.Duty{
		Slot: uint64(block5.DenebBlinded.Message.Slot),
		Type: core.DutyBuilderProposer,
	}

	// Submit all duties
	incl1, err := core.NewVersionedAttestation(att1)
	require.NoError(t, err)
	err = incl.Submitted(att1Duty, "", incl1, 0)
	require.NoError(t, err)
	err = incl.Submitted(agg2Duty, "", core.NewSignedAggregateAndProof(agg2), 0)
	require.NoError(t, err)
	incl3, err := core.NewVersionedAttestation(att3)
	require.NoError(t, err)
	err = incl.Submitted(att3Duty, "", incl3, 0)
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
	//TODO: fix after go-eth2-client make util functions for Data field
	att2Root, err := agg2.Message.Aggregate.Data.HashTreeRoot()
	require.NoError(t, err)
	// Add some random aggregation bits to the attestation
	addRandomBits(att1.Deneb.AggregationBits)
	//TODO: fix after go-eth2-client make util functions for AggregationBits field
	addRandomBits(agg2.Message.Aggregate.AggregationBits)

	block := block{
		Slot: block4Duty.Slot,
		AttestationsByDataRoot: map[eth2p0.Root]*eth2spec.VersionedAttestation{
			att1Root: att1,
			att2Root: {Version: eth2spec.DataVersionDeneb, Deneb: agg2.Message.Aggregate},
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
