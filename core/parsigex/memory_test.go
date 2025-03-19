// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	memExFunc := parsigex.NewMemExFunc(n)

	var received []tuple

	var exes []core.ParSigEx
	for i := range n {
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

	for i := range n {
		set := make(core.ParSignedDataSet)
		set[pubkey] = core.ParSignedData{
			SignedData: nil,
			ShareIdx:   i,
		}

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
