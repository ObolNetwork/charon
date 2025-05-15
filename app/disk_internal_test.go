// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"os"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestCalculateTrackerDelay(t *testing.T) {
	tests := []struct {
		name         string
		slotDuration time.Duration
		slotDelay    uint64
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

			now := time.Now()
			genesis := now.Add(-test.slotDuration * currentSlot)

			eth2util.SetCustomNetworkForTest(&eth2util.Network{
				ChainID:               0,
				Name:                  "simnet",
				GenesisForkVersionHex: "0x00000000",
				GenesisTimestamp:      genesis.Unix(),
				CapellaHardFork:       "0x03000000",
				SlotDuration:          test.slotDuration,
				SlotsPerEpoch:         16,
			})

			fromSlot := calculateTrackerDelay(now)
			require.EqualValues(t, currentSlot+test.slotDelay, fromSlot)
		})
	}
	set := beaconmock.ValidatorSetA
	for i := range len(set) {
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

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()

	tmpFile, err := os.CreateTemp(tempDir, "testfile")
	require.NoError(t, err)

	require.NoError(t, os.Remove(tmpFile.Name()))

	exists := FileExists(tmpFile.Name())
	require.False(t, exists)
}
