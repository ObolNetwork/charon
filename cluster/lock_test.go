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

func TestVerifyLockRejectsDuplicateDistributedKeys(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Duplicate validator 0 so two entries share the same distributed public key.
	lock.Validators = append(lock.Validators, lock.Validators[0])

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate distributed validator public key")
}

func TestVerifyLockRejectsIdentityPointShare(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	// Replace one share with the BLS G1 identity point (0xc0 followed by zeros).
	identityPoint := make([]byte, 48)
	identityPoint[0] = 0xc0
	lock.Validators[0].PubShares[0] = identityPoint

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "identity point share")
}

func TestVerifyLockRejectsExtraShareNotOnPolynomial(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	// Keep first threshold (3) shares intact so the main reconstruction passes;
	// replace the extra share with the DV pubkey — a valid, unique, non-identity
	// G1 point that does not lie on the share polynomial.
	lock.Validators[0].PubShares[3] = append([]byte(nil), lock.Validators[0].PubKey...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "extra share does not lie on distributed key polynomial")
}

func TestVerifyLockRejectsDuplicatePublicShares(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random)

	// Duplicate one share so the share list is not unique.
	lock.Validators[0].PubShares[1] = append([]byte(nil), lock.Validators[0].PubShares[0]...)

	err := lock.VerifySignatures(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate public share")
}
