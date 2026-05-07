// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestVerifyLock(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)
	require.NoError(t, lock.Definition.VerifySignatures(nil))
	require.NoError(t, lock.VerifySignatures(nil))
}

func TestVerifyLockRejectsMismatchedPublicShares(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Tamper validator shares so they no longer reconstruct validator 0 group key.
	lock.Validators[0].PubShares = append([][]byte(nil), lock.Validators[1].PubShares...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "public shares do not reconstruct distributed public key")
}
