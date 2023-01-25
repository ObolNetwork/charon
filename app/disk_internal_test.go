// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package app

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestLoadLock(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)

	b, err := json.MarshalIndent(lock, "", " ")
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	filename := path.Join(dir, "cluster-lock.json")

	err = os.WriteFile(filename, b, 0o644)
	require.NoError(t, err)

	conf := Config{LockFile: filename}
	actual, err := loadLock(context.Background(), conf)
	require.NoError(t, err)

	b2, err := json.Marshal(actual)
	require.NoError(t, err)
	require.JSONEq(t, string(b), string(b2))
}

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

		feeRecipientByPubkey := make(map[eth2p0.BLSPubKey]string)
		for _, pubkey := range clone.PublicKeys() {
			feeRecipientByPubkey[pubkey] = "0xdead"
		}

		fn := setFeeRecipient(bmock, clone.PublicKeys(), feeRecipientByPubkey)
		err = fn(context.Background(), core.Slot{SlotsPerEpoch: 1})
		require.NoError(t, err)

		require.Equal(t, active, len(clone)-(i+1))
	}
}
