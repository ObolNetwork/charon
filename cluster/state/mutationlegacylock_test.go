// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

func TestZeroCluster(t *testing.T) {
	_, err := state.TypeLegacyLock.Transform(state.Cluster{Name: "foo"}, state.SignedMutation{})
	require.ErrorContains(t, err, "legacy lock not first mutation")
}

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
		cluster, err := signed.Transform(state.Cluster{})
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

	t.Run("cluster loaded from lock", func(t *testing.T) {
		cluster, err := state.Load("testdata/lock.json")
		require.NoError(t, err)
		testutil.RequireGoldenJSON(t, cluster, testutil.WithFilename("TestLegacyLock_cluster.golden"))
	})

	t.Run("cluster loaded from state", func(t *testing.T) {
		b, err := json.Marshal([]state.SignedMutation{signed})
		require.NoError(t, err)
		file := path.Join(t.TempDir(), "state.json")
		require.NoError(t, os.WriteFile(file, b, 0o644))

		cluster, err := state.Load(file)
		require.NoError(t, err)
		testutil.RequireGoldenJSON(t, cluster, testutil.WithFilename("TestLegacyLock_cluster.golden"))
	})
}
