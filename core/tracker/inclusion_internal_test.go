// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"math/rand"
	"testing"

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

	bmock.BlockAttestationsFunc = func(_ context.Context, _ string) ([]*eth2p0.Attestation, error) {
		return []*eth2p0.Attestation{
			{AggregationBits: bits1, Data: attData},
			{AggregationBits: bits2, Data: attData},
			{AggregationBits: bits3, Data: attData},
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

		ok, err := att.AggregationBits.Contains(bits1)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = att.AggregationBits.Contains(bits2)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = att.AggregationBits.Contains(bits3)
		require.NoError(t, err)
		require.True(t, ok)

		close(done)
	}

	err = incl.checkBlock(ctx, int64(attData.Slot))
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
	att1 := testutil.RandomAttestation()
	att1Duty := core.NewAttesterDuty(int64(att1.Data.Slot))

	agg2 := testutil.RandomSignedAggregateAndProof()
	agg2Duty := core.NewAggregatorDuty(int64(agg2.Message.Aggregate.Data.Slot))

	att3 := testutil.RandomAttestation()
	att3Duty := core.NewAttesterDuty(int64(att3.Data.Slot))

	block4 := testutil.RandomCapellaVersionedSignedBeaconBlock()
	block4Duty := core.NewProposerDuty(int64(block4.Capella.Message.Slot))

	block5 := testutil.RandomCapellaVersionedSignedBlindedBeaconBlock()
	block5.Capella.Message.Body.Graffiti = eth2wrap.GetSyntheticGraffiti() // Ignored, not included or missed.
	block5Duty := core.NewBuilderProposerDuty(int64(block5.Capella.Message.Slot))

	// Submit all duties
	err := incl.Submitted(att1Duty, "", core.NewAttestation(att1), 0)
	require.NoError(t, err)
	err = incl.Submitted(agg2Duty, "", core.NewSignedAggregateAndProof(agg2), 0)
	require.NoError(t, err)
	err = incl.Submitted(att3Duty, "", core.NewAttestation(att3), 0)
	require.NoError(t, err)

	coreBlock4, err := core.NewVersionedSignedBeaconBlock(block4)
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
	for i := 0; i < rand.Intn(4); i++ {
		list.SetBitAt(uint64(rand.Intn(int(list.Len()))), true)
	}
}
