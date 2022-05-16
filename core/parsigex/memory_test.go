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

	var exes []core.ShareSigExchange
	for i := 0; i < n; i++ {
		i := i
		ex := memExFunc()
		ex.Subscribe(func(ctx context.Context, duty core.Duty, set core.ShareSignedDataSet) error {
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
		set := make(core.ShareSignedDataSet)
		set[pubkey] = core.ShareSignedData{ShareIdx: i}

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
