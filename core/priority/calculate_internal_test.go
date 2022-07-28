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

package priority

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

func TestCalculateResults(t *testing.T) {
	const (
		N = 5 // Number of nodes in the cluster
		Q = 3 // Quorum (not accurate but good enough for this example).
		F = 1 // Faulty
	)
	var (
		// Define priority sets
		v1 = []string{"v1"}       // v1 nodes only support v1
		v2 = []string{"v2", "v1"} // v2 nodes support v2 and v1
		v3 = []string{"v3", "v2"} // v3 nodes support v3 and v2 but not v1 anymore.

		// Used for testing deterministic ordering
		xy = []string{"x", "y"}
		yx = []string{"y", "x"}
	)

	tests := []struct {
		Name       string
		Priorities [][]string
		Result     []string
		Scores     []int64
		Slot       int64 // Defaults to test index if not provided.
	}{
		{
			Name:       "1*v1",
			Priorities: pl(v1),
			Result:     []string{}, // Insufficient v1s
		},
		{
			Name:       "Q-1*v1",
			Priorities: pl(v1, v1),
			Result:     []string{}, // Insufficient v1s
		},
		{
			Name:       "Q*v1",
			Priorities: pl(v1, v1, v1),
			Result:     []string{"v1"}, // Quorum v1s
			Scores:     []int64{3000},
		},
		{
			Name:       "N*v1",
			Priorities: pl(v1, v1, v1, v1, v1),
			Result:     []string{"v1"}, // All v1s
			Scores:     []int64{5000},
		},
		{
			Name:       "N-1*v1,1*v2",
			Priorities: pl(v1, v1, v1, v1, v2),
			Result:     []string{"v1"}, // Insufficient v2s
			Scores:     []int64{4999},
		},
		{
			Name:       "N-Q*v1,Q*v2",
			Priorities: pl(v1, v1, v2, v2, v2),
			Result:     []string{"v1", "v2"}, // More nodes support v1
			Scores:     []int64{4997, 3000},
		},
		{
			Name:       "N*v2",
			Priorities: pl(v2, v2, v2, v2, v2),
			Result:     []string{"v2", "v1"}, // Most nodes support v1 and v2, but v2 takes precedence.
			Scores:     []int64{5000, 4995},
		},
		{
			Name:       "N-1*v2,1*down",
			Priorities: pl(v2, v2, v2, v2),
			Result:     []string{"v2", "v1"}, // Most nodes support v1 and v2, but v2 takes precedence.
			Scores:     []int64{4000, 3996},
		},
		{
			Name:       "Q-1*v2,3*down",
			Priorities: pl(v2, v2),
			Result:     []string{}, // Insufficient nodes support v1 or v2.
			Scores:     []int64{5000},
		},
		{
			Name:       "1*v1,N-1*v2",
			Priorities: pl(v1, v2, v2, v2, v2),
			Result:     []string{"v1", "v2"}, // More nodes support v1. Note a single node can cause flapping of cluster level ordering.
			Scores:     []int64{4996, 4000},
		},
		{
			Name:       "1*v1,N-2*v2,1*down",
			Priorities: pl(v1, v2, v2, v2),
			Result:     []string{"v1", "v2"}, // More nodes support v1 than v2.
			Scores:     []int64{3997, 3000},
		},
		{
			Name:       "1*v1,Q-1*v2,2*down",
			Priorities: pl(v1, v2, v2),
			Result:     []string{"v1"}, // More nodes support v1. Insufficient nodes support than port v2.
			Scores:     []int64{2998},
		},
		{
			Name:       "1*v1,N-2*v2,1*v3",
			Priorities: pl(v1, v2, v2, v2, v3),
			Result:     []string{"v2", "v1"}, // More nodes support v2 than v1 since v3 also supports v2, but insufficient nodes support v3.
			Scores:     []int64{3999, 3997},
		},
		{
			Name:       "2*v1,N-3*v2,1*v3",
			Priorities: pl(v1, v1, v2, v2, v3),
			Result:     []string{"v1", "v2"}, // More nodes support v1 than v2 since v3 insufficient nodes support v3. Note a single node can cause flapping of cluster level ordering.
			Scores:     []int64{3998, 2999},
		},
		{
			Name:       "1*v1,1*v2,Q*v3",
			Priorities: pl(v1, v2, v3, v3, v3),
			Result:     []string{"v2", "v3"}, // More nodes support v2 than v3, insufficient nodes support v1. Upgrade forced once quorum nodes do not support old version.
			Scores:     []int64{3997, 3000},
		},
		{
			Name:       "2*v1,Q*v3",
			Priorities: pl(v1, v1, v3, v3, v3),
			Result:     []string{"v3", "v2"}, // Most nodes support v2 and v3, v3 takes precedence. Once “all” (excluding incompatible minority) support both v2 and v3, then the cluster upgrades again.
			Scores:     []int64{3000, 2997},
		},
		{
			Name:       "deterministic ordering slot 1",
			Priorities: pl(xy, xy, yx, yx),
			Slot:       1,
			Result:     xy,                  // X as always before Y, since we use lower peer IDs for tie breaking.
			Scores:     []int64{3998, 3998}, // Tied scores: Users of priority protocol can decide how to handle, either something fancy, or just using the provided order.
		},
		{
			Name:       "deterministic ordering slot 9",
			Priorities: pl(xy, xy, yx, yx),
			Slot:       9,
			Result:     xy, // Same input (except for slot), same result.
			Scores:     []int64{3998, 3998},
		},
	}

	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var msgs []*pbv1.PriorityMsg
			for j, prioritySet := range test.Priorities {
				if test.Slot == 0 {
					test.Slot = int64(i)
				}
				msgs = append(msgs, &pbv1.PriorityMsg{
					Topics: []*pbv1.PriorityTopicProposal{
						{
							Topic:      "versions",
							Priorities: prioritySet,
						},
					},
					PeerId: fmt.Sprint(j),
					Slot:   test.Slot,
				})
			}

			// Shuffle since function should be deterministic.
			rand.Shuffle(len(msgs), func(i, j int) {
				msgs[i], msgs[j] = msgs[j], msgs[i]
			})

			result, err := calculateResult(msgs, Q)
			require.NoError(t, err)
			require.Len(t, result.Topics, 1)
			if len(test.Result) > 0 {
				var actualResult []string
				var actualScores []int64
				for _, prio := range result.Topics[0].Priorities {
					actualResult = append(actualResult, prio.Priority)
					actualScores = append(actualScores, prio.Score)
				}
				require.Equal(t, test.Result, actualResult)
				if len(test.Scores) != 0 {
					require.Equal(t, test.Scores, actualScores)
				}
			} else {
				require.Empty(t, result.Topics[0].Priorities)
			}
		})
	}
}

// pl returns a slice of priority sets. It is an abridged convenience function.
func pl(pl ...[]string) [][]string {
	return pl
}
