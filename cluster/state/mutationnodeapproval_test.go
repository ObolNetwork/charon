// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

// setIncrementingTime sets the time function to an deterministic incrementing value
// for the duration of the test.
func setIncrementingTime(t *testing.T) {
	t.Helper()

	ts := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	state.SetNowFuncForT(t, func() time.Time {
		defer func() {
			ts = ts.Add(time.Minute)
		}()

		return ts
	})
}

func TestNodeApprovals(t *testing.T) {
	setIncrementingTime(t)

	lock, secrets, _ := cluster.NewForT(t, 1, 3, 4, 1)

	parent := testutil.RandomArray32()

	var approvals []state.SignedMutation
	for _, secret := range secrets {
		approval, err := state.SignNodeApproval(parent, secret)
		require.NoError(t, err)

		approvals = append(approvals, approval)
	}

	composite, err := state.NewNodeApprovalsComposite(approvals)
	require.NoError(t, err)

	t.Run("json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, composite)
	})

	t.Run("unmarshal", func(t *testing.T) {
		b, err := json.Marshal(composite)
		require.NoError(t, err)
		var composite2 state.SignedMutation
		testutil.RequireNoError(t, json.Unmarshal(b, &composite2))
		require.EqualValues(t, composite, composite2)
	})

	t.Run("transform", func(t *testing.T) {
		cluster, err := state.NewClusterFromLock(lock)
		require.NoError(t, err)

		cluster2, err := composite.Transform(cluster)
		require.NoError(t, err)

		require.Equal(t, cluster, cluster2)
	})
}
