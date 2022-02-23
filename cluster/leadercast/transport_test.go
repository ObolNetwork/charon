// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package leadercast_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/leadercast"
	"github.com/obolnetwork/charon/types"
)

func TestMemTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trFunc := leadercast.NewMemTransportFunc(ctx)

	const (
		n     = 3
		slots = 3
	)
	var casts []*leadercast.LeaderCast
	for i := 0; i < n; i++ {
		c := leadercast.New(trFunc(), i, n)
		casts = append(casts, c)
		go func() {
			require.NoError(t, c.Start())
		}()

		t.Cleanup(c.Stop)
	}

	resolved := make(chan []byte, slots*n)
	for i := 0; i < slots; i++ {
		duty := types.Duty{Slot: i}
		for j := 0; j < n; j++ {
			go func(slot, node int) {
				data, err := casts[node].ResolveDuty(ctx, duty, []byte(fmt.Sprintf("c%d#%d", node, slot)))
				require.NoError(t, err)
				resolved <- data
			}(i, j)
		}
	}

	var actual []string
	for i := 0; i < slots*n; i++ {
		actual = append(actual, string(<-resolved))
	}

	expects := []string{"c0#0", "c1#1", "c2#2"}
	for _, expect := range expects {
		var count int
		for _, resolved := range actual {
			if resolved == expect {
				count++
			}
		}
		require.Equal(t, n, count, expect)
	}
}
