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

package parsigex_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestMemEx -update -clean

func TestMemEx(t *testing.T) {
	const n = 3

	ctx := context.Background()
	pubkey := testutil.RandomCorePubKey(t)

	memExFunc := parsigex.NewMemExFunc()

	var received []tuple

	var exes []core.ParSigEx
	for i := 0; i < n; i++ {
		i := i
		ex := memExFunc()
		ex.Subscribe(func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
			require.NotEqual(t, i, set[pubkey].ShareIdx, "received from self")

			received = append(received, tuple{
				Target: i,
				Source: set[pubkey].ShareIdx,
			})

			return nil
		})
		exes = append(exes, ex)
	}

	for i := 0; i < n; i++ {
		set := make(core.ParSignedDataSet)
		set[pubkey] = core.ParSignedData{ShareIdx: i}

		err := exes[i].Broadcast(ctx, core.Duty{}, set)
		require.NoError(t, err)
	}

	sort.Slice(received, func(i, j int) bool {
		if received[i].Source != received[j].Source {
			return received[i].Source < received[j].Source
		}

		return received[i].Target < received[j].Target
	})

	testutil.RequireGoldenJSON(t, received)
}

type tuple struct {
	Target int
	Source int
}
