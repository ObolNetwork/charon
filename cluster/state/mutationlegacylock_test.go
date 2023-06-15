// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update

func TestZeroCluster(t *testing.T) {
	_, err := state.TypeLegacyLock.Transform(state.Cluster{Name: "foo"}, &pbv1.SignedMutation{})
	require.ErrorContains(t, err, "legacy lock not first mutation")
}

func TestLegacyLock(t *testing.T) {
	lockJON, err := os.ReadFile("testdata/lock.json")
	require.NoError(t, err)

	var lock cluster.Lock
	testutil.RequireNoError(t, json.Unmarshal(lockJON, &lock))

	signed, err := state.NewLegacyLock(lock)
	require.NoError(t, err)

	t.Run("proto", func(t *testing.T) {
		testutil.RequireGoldenProto(t, signed)
	})

	t.Run("cluster", func(t *testing.T) {
		cluster, err := state.Materialise(&pbv1.SignedMutationList{Mutations: []*pbv1.SignedMutation{signed}})
		require.NoError(t, err)
		require.Equal(t, lock.LockHash, cluster.Hash[:])
		RequireGoldenCluster(t, cluster)
	})

	b, err := proto.Marshal(signed)
	require.NoError(t, err)

	signed2 := new(pbv1.SignedMutation)
	testutil.RequireNoError(t, proto.Unmarshal(b, signed2))

	t.Run("proto again", func(t *testing.T) {
		testutil.RequireGoldenProto(t, signed2, testutil.WithFilename("TestLegacyLock_proto.golden"))
	})

	t.Run("cluster loaded from lock", func(t *testing.T) {
		cluster, err := state.Load("testdata/lock.json", nil)
		require.NoError(t, err)
		RequireGoldenCluster(t, cluster, testutil.WithFilename("TestLegacyLock_cluster.golden"))
	})

	t.Run("cluster loaded from state", func(t *testing.T) {
		b, err := proto.Marshal(&pbv1.SignedMutationList{Mutations: []*pbv1.SignedMutation{signed}})
		require.NoError(t, err)
		file := path.Join(t.TempDir(), "state.pb")
		require.NoError(t, os.WriteFile(file, b, 0o644))

		cluster, err := state.Load(file, nil)
		require.NoError(t, err)
		RequireGoldenCluster(t, cluster, testutil.WithFilename("TestLegacyLock_cluster.golden"))
	})
}
