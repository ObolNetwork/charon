// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestCalculateTrackerDelay(t *testing.T) {
	tests := []struct {
		name         string
		slotDuration time.Duration
		slotDelay    int64
	}{
		{
			name:         "slow slots",
			slotDuration: time.Second,
			slotDelay:    11,
		},
		{
			name:         "fast slots",
			slotDuration: time.Second * 12,
			slotDelay:    2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const currentSlot = 100

			ctx := context.Background()
			now := time.Now()
			genesis := now.Add(-test.slotDuration * currentSlot)

			bmock, err := beaconmock.New(
				beaconmock.WithSlotDuration(test.slotDuration),
				beaconmock.WithGenesisTime(genesis),
			)
			require.NoError(t, err)

			fromSlot, err := calculateTrackerDelay(ctx, bmock, now)
			require.NoError(t, err)
			require.EqualValues(t, currentSlot+test.slotDelay, fromSlot)
		})
	}
}

func TestSetFeeRecipient(t *testing.T) {
	set := beaconmock.ValidatorSetA
	for i := 0; i < len(set); i++ {
		clone, err := set.Clone()
		require.NoError(t, err)

		// Make i+1 validators inactive
		inactive := i + 1
		for index, validator := range clone {
			validator.Status = eth2v1.ValidatorStatePendingQueued
			clone[index] = validator
			inactive--
			if inactive == 0 {
				break
			}
		}

		bmock, err := beaconmock.New(beaconmock.WithValidatorSet(clone))
		require.NoError(t, err)

		// Only expect preparations for active validators.
		var active int
		bmock.SubmitProposalPreparationsFunc = func(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
			if len(preparations) == 0 {
				return errors.New("empty slice")
			}

			active = len(preparations)

			return nil
		}

		fn := setFeeRecipient(bmock, func(core.PubKey) string {
			return "0xdead"
		})
		err = fn(context.Background(), core.Slot{SlotsPerEpoch: 1})
		require.NoError(t, err)

		require.Equal(t, active, len(clone)-(i+1))
	}
}
