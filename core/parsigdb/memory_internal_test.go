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

package parsigdb

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
)

func TestGetThresholdMatching(t *testing.T) {
	const n = 4

	tests := []struct {
		name   string
		input  []int
		output []int
	}{
		{
			name:   "empty",
			output: nil,
		},
		{
			name:   "all identical exact threshold",
			input:  []int{0, 0, 0},
			output: []int{0, 1, 2},
		},
		{
			name:   "all identical above threshold",
			input:  []int{0, 0, 0, 0},
			output: nil,
		},
		{
			name:   "one odd",
			input:  []int{0, 0, 1, 0},
			output: []int{0, 1, 3},
		},
		{
			name:   "two odd",
			input:  []int{0, 0, 1, 1},
			output: nil,
		},
	}

	slot := testutil.RandomSlot()
	valIdx := testutil.RandomVIdx()
	roots := []eth2p0.Root{
		testutil.RandomRoot(),
		testutil.RandomRoot(),
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test different msg type using providers.
			providers := map[string]func(int) core.ParSignedData{
				"SyncCommitteeMessage": func(i int) core.ParSignedData {
					msg := &altair.SyncCommitteeMessage{
						Slot:            slot,
						BeaconBlockRoot: roots[test.input[i]], // Vary root based on input.
						ValidatorIndex:  valIdx,
						Signature:       testutil.RandomEth2Signature(),
					}

					return core.NewPartialSignedSyncMessage(msg, i+1)
				},
				"Selection": func(i int) core.ParSignedData {
					// Message is constant
					msg := &eth2exp.BeaconCommitteeSelection{
						ValidatorIndex: valIdx,
						Slot:           eth2p0.Slot(test.input[i]), // Vary slot based on input
						SelectionProof: testutil.RandomEth2Signature(),
					}

					return core.NewPartialSignedBeaconCommitteeSelection(msg, i+1)
				},
			}

			for name, provider := range providers {
				t.Run(name, func(t *testing.T) {
					var datas []core.ParSignedData
					for i := 0; i < len(test.input); i++ {
						datas = append(datas, provider(i))
					}

					th := cluster.Threshold(n)

					out, ok, err := getThresholdMatching(1, datas, th)
					require.NoError(t, err)
					require.Equal(t, len(out) == th, ok)

					var expect []core.ParSignedData
					for _, i := range test.output {
						expect = append(expect, datas[i])
					}

					require.Equal(t, expect, out)
				})
			}
		})
	}
}

func TestMemDBThreshold(t *testing.T) {
	const (
		th = 7
		n  = 10
	)

	db := NewMemDB(th)
	timesCalled := 0
	db.SubscribeThreshold(func(_ context.Context, _ core.Duty, _ core.PubKey, _ []core.ParSignedData) error {
		timesCalled++

		return nil
	})

	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomAttestation()
	for i := 0; i < n; i++ {
		err := db.StoreExternal(context.Background(), core.NewAttesterDuty(123), core.ParSignedDataSet{
			pubkey: core.NewPartialAttestation(att, i+1),
		})
		require.NoError(t, err)
	}

	require.Equal(t, 1, timesCalled)
}
