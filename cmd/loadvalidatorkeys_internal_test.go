// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// setupValidatorKeys builds a cluster lock and writes operator 0's key shares (one per validator,
// as keystore-insecure-<validatorIdx>.json) into a fresh validator_keys directory. It returns the
// lock and the directory.
func setupValidatorKeys(t *testing.T) (cluster.Lock, string) {
	t.Helper()

	const (
		valAmt      = 3
		operatorAmt = 4
	)

	random := rand.New(rand.NewSource(0))

	lock, _, keyShares := cluster.NewForT(t, valAmt, operatorAmt, operatorAmt, 0, random)

	var op0Shares []tbls.PrivateKey
	for _, share := range keyShares {
		op0Shares = append(op0Shares, share[0])
	}

	dir := filepath.Join(t.TempDir(), "validator_keys")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, keystore.StoreKeysInsecure(op0Shares, dir, keystore.ConfirmInsecureKeys))

	return lock, dir
}

// removeKeystore deletes the keystore-insecure-<idx>.json/.txt pair from dir.
func removeKeystore(t *testing.T, dir string, idx int) {
	t.Helper()

	for _, ext := range []string{".json", ".txt"} {
		require.NoError(t, os.Remove(filepath.Join(dir, "keystore-insecure-"+strconv.Itoa(idx)+ext)))
	}
}

func TestLoadValidatorShares(t *testing.T) {
	ctx := t.Context()

	t.Run("strict full set", func(t *testing.T) {
		lock, dir := setupValidatorKeys(t)

		shares, err := loadValidatorShares(ctx, lock, dir, false)
		require.NoError(t, err)
		require.Len(t, shares, 3)
	})

	t.Run("strict rejects contiguous subset", func(t *testing.T) {
		lock, dir := setupValidatorKeys(t)
		removeKeystore(t, dir, 2) // leaves keystore-insecure-0 and -1 (SequencedKeys passes)

		_, err := loadValidatorShares(ctx, lock, dir, false)
		require.ErrorContains(t, err, "allow-incomplete-keystores")
	})

	t.Run("strict rejects gapped subset", func(t *testing.T) {
		lock, dir := setupValidatorKeys(t)
		removeKeystore(t, dir, 0)
		removeKeystore(t, dir, 1) // leaves only keystore-insecure-2 (out of sequence)

		_, err := loadValidatorShares(ctx, lock, dir, false)
		require.ErrorContains(t, err, "out of sequence")
	})

	t.Run("lenient allows gapped subset", func(t *testing.T) {
		lock, dir := setupValidatorKeys(t)
		removeKeystore(t, dir, 0)
		removeKeystore(t, dir, 1) // leaves only keystore-insecure-2 (validator index 2)

		shares, err := loadValidatorShares(ctx, lock, dir, true)
		require.NoError(t, err)
		require.Len(t, shares, 1)

		_, ok := shares[core.PubKey(lock.Validators[2].PublicKeyHex())]
		require.True(t, ok, "expected validator 2 present in result")
	})

	t.Run("lenient allows full set", func(t *testing.T) {
		lock, dir := setupValidatorKeys(t)

		shares, err := loadValidatorShares(ctx, lock, dir, true)
		require.NoError(t, err)
		require.Len(t, shares, 3)
	})
}
