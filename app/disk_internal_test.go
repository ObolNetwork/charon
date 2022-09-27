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

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
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
	actual, err := loadLock(conf)
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
