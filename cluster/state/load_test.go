// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state_test

import (
	"encoding/json"
	"math/rand"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/testutil"
)

func TestLoadLegacy(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			testLoadLegacy(t, version)
		})
	}
}

func testLoadLegacy(t *testing.T, version string) {
	t.Helper()
	n := 4 + rand.Intn(6)
	k := cluster.Threshold(n)

	var opts []func(*cluster.Definition)
	opts = append(opts, cluster.WithVersion(version))
	if version < "v1.5.0" {
		opts = append(opts, cluster.WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()))
	}

	lock, _, _ := cluster.NewForT(t, rand.Intn(10), k, n, 0, opts...)

	b, err := json.MarshalIndent(lock, "", "  ")
	require.NoError(t, err)

	file := path.Join(t.TempDir(), "lock.json")

	err = os.WriteFile(file, b, 0o644)
	require.NoError(t, err)

	cluster, err := state.Load(file, nil)
	require.NoError(t, err)

	require.Equal(t, lock.LockHash, cluster.Hash)
	require.Equal(t, lock.Name, cluster.Name)
	require.EqualValues(t, lock.Threshold, cluster.Threshold)
	require.Equal(t, lock.DKGAlgorithm, cluster.DkgAlgorithm)
	require.Equal(t, lock.ForkVersion, cluster.ForkVersion)
	require.Equal(t, len(lock.Validators), len(cluster.Validators))
	require.Equal(t, len(lock.Operators), len(cluster.Operators))

	for i, validator := range cluster.Validators {
		require.Equal(t, lock.Validators[i].PubKey, validator.PublicKey)
		require.Equal(t, lock.Validators[i].PubShares, validator.PubShares)
		require.Equal(t, lock.ValidatorAddresses[i].FeeRecipientAddress, validator.FeeRecipientAddress)
		require.Equal(t, lock.ValidatorAddresses[i].WithdrawalAddress, validator.WithdrawalAddress)
	}

	for i, operator := range cluster.Operators {
		require.Equal(t, lock.Operators[i].Address, operator.Address)
		require.Equal(t, lock.Operators[i].ENR, operator.Enr)
	}
}
