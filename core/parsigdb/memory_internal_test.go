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
	"testing"

	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
)

func TestCalculateOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		output   []int
		provider int
	}{
		{
			name:   "empty",
			output: nil,
		},
		{
			name:   "all identical",
			input:  []int{0, 0, 0, 0},
			output: []int{0, 1, 2},
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

	commIdx := testutil.RandomCommIdx()
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
				"Subscription": func(i int) core.ParSignedData {
					// Message is constant
					msg := &eth2exp.BeaconCommitteeSubscription{
						ValidatorIndex:   valIdx,
						Slot:             slot,
						CommitteeIndex:   commIdx,
						CommitteesAtSlot: 99,
						SlotSignature:    testutil.RandomEth2Signature(),
					}
					// Vary length based on input
					commLength := uint64(test.input[i])

					return core.NewPartialSignedBeaconCommitteeSubscription(msg, commLength, i+1)
				},
			}

			for name, provider := range providers {
				t.Run(name, func(t *testing.T) {
					var datas []core.ParSignedData
					for i := 0; i < len(test.input); i++ {
						datas = append(datas, provider(i))
					}

					out, ok, err := getThresholdMatching(datas, cluster.Threshold(len(datas)))
					require.NoError(t, err)
					require.Equal(t, len(test.output) > 0, ok)

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
