// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

func TestLegacyLock(t *testing.T) {
	lockJON, err := os.ReadFile("testdata/lock.json")
	require.NoError(t, err)

	var lock cluster.Lock
	testutil.RequireNoError(t, json.Unmarshal(lockJON, &lock))

	signed, err := state.NewLegacyLock(lock)
	require.NoError(t, err)

	t.Run("json", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, signed)
	})

	t.Run("cluster", func(t *testing.T) {
		cluster, err := signed.Mutation.Type.Transform(state.Cluster{}, signed)
		require.NoError(t, err)
		testutil.RequireGoldenJSON(t, cluster)
	})

	b, err := json.MarshalIndent(signed, "", "  ")
	require.NoError(t, err)

	var signed2 state.SignedMutation
	testutil.RequireNoError(t, json.Unmarshal(b, &signed2))

	t.Run("json again", func(t *testing.T) {
		testutil.RequireGoldenJSON(t, signed2, testutil.WithFilename("TestLegacyLock_json.golden"))
	})
}
