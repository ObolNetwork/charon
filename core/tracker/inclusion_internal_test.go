// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

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

		block := testutil.RandomElectraVersionedSignedProposal()
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

		block := testutil.RandomElectraVersionedSignedProposal()
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

		block := testutil.RandomElectraVersionedSignedProposal()
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
