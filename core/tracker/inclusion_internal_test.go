// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestInclusion(t *testing.T) {
	//  Setup inclusionCore with a mock missedFunc and attIncludedFunc
	var missed, included []core.Duty
	incl := &inclusionCore{
		missedFunc: func(ctx context.Context, sub submission) {
			missed = append(missed, sub.Duty)
		},
		attIncludedFunc: func(ctx context.Context, sub submission, block block) {
			included = append(included, sub.Duty)
		},
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

	// Submit the duties
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

	// Create a mock block with the first two attestations.
	att1Root, err := att1.HashTreeRoot()
	require.NoError(t, err)
	att2Root, err := agg2.Message.Aggregate.HashTreeRoot()
	require.NoError(t, err)

	// Check the block
	incl.CheckBlock(context.Background(), block{
		Slot: block4Duty.Slot,
		Attestations: map[eth2p0.Root]*eth2p0.Attestation{
			att1Root: att1,
			att2Root: agg2.Message.Aggregate,
		},
	})
	// Assert that the first two duties were included
	require.Equal(t, []core.Duty{att1Duty, agg2Duty}, included)

	// Trim the duties
	incl.Trim(context.Background(), att3Duty.Slot)
	// Assert that the third duty was missed
	require.Equal(t, []core.Duty{att3Duty}, missed)
}
