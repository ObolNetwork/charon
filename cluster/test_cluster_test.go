// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestNewCluster(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 3, seed, random)
	require.NoError(t, lock.VerifyHashes())
	require.NoError(t, lock.VerifySignatures(nil))
}
