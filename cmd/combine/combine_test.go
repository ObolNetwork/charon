// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package combine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd/combine"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

func TestCombineNoLockfile(t *testing.T) {
	td := t.TempDir()
	od := t.TempDir()
	err := combine.Combine(context.Background(), td, od, false)
	require.ErrorContains(t, err, "lock file not found")
}

func TestCombineCannotLoadKeystore(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		lf, err := os.OpenFile(filepath.Join(ep, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
		require.NoError(t, err)

		require.NoError(t, json.NewEncoder(lf).Encode(lock))
	}

	require.NoError(t, os.RemoveAll(filepath.Join(dir, "node0")))

	err := combine.Combine(context.Background(), dir, od, false, combine.WithInsecureKeysForT(t))
	require.Error(t, err)
}

// This test exists because of https://github.com/ObolNetwork/charon/issues/2151.
func TestCombineLotsOfVals(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 100, 3, 4, 0)
	combineTest(t, lock, shares)
}

func TestCombine(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)
	combineTest(t, lock, shares)
}

func combineTest(t *testing.T, lock cluster.Lock, shares [][]tbls.PrivateKey) {
	t.Helper()

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tbls.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tbls.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		lf, err := os.OpenFile(filepath.Join(ep, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
		require.NoError(t, err)

		require.NoError(t, json.NewEncoder(lf).Encode(lock))
	}

	err := combine.Combine(context.Background(), dir, od, true, combine.WithInsecureKeysForT(t))
	require.NoError(t, err)

	keyFiles, err := keystore.LoadFilesUnordered(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, keyFile := range keyFiles {
		pk, err := tbls.SecretToPublicKey(keyFile.PrivateKey)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", keyFile.PrivateKey)
	}

	for _, exp := range expectedData {
		require.Contains(t, keysMap, exp.pubkey)
		require.Equal(t, exp.secret, keysMap[exp.pubkey])
	}

	require.Len(t, keysMap, len(expectedData))
}

func TestCombineTwiceWithoutForceFails(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tbls.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tbls.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tbls.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tbls.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tbls.PrivateKey, len(lock.Definition.Operators))

	// populate key sets
	for enrIdx := 0; enrIdx < len(lock.Definition.Operators); enrIdx++ {
		keyIdx := enrIdx
		for dvIdx := 0; dvIdx < lock.NumValidators; dvIdx++ {
			secrets[enrIdx] = append(secrets[enrIdx], rawSecrets[keyIdx])
			keyIdx += len(lock.Definition.Operators)
		}
	}

	for idx, keys := range secrets {
		ep := filepath.Join(dir, fmt.Sprintf("node%d", idx))

		vk := filepath.Join(ep, "validator_keys")

		require.NoError(t, os.Mkdir(ep, 0o755))
		require.NoError(t, os.Mkdir(vk, 0o755))
		require.NoError(t, keystore.StoreKeysInsecure(keys, vk, keystore.ConfirmInsecureKeys))

		lf, err := os.OpenFile(filepath.Join(ep, "cluster-lock.json"), os.O_WRONLY|os.O_CREATE, 0o755)
		require.NoError(t, err)

		require.NoError(t, json.NewEncoder(lf).Encode(lock))
	}

	err := combine.Combine(context.Background(), dir, od, false, combine.WithInsecureKeysForT(t))
	require.NoError(t, err)

	err = combine.Combine(context.Background(), dir, od, false, combine.WithInsecureKeysForT(t))
	require.Error(t, err)

	keyFiles, err := keystore.LoadFilesUnordered(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, keyFile := range keyFiles {
		pk, err := tbls.SecretToPublicKey(keyFile.PrivateKey)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", keyFile.PrivateKey)
	}

	for _, exp := range expectedData {
		require.Contains(t, keysMap, exp.pubkey)
		require.Equal(t, exp.secret, keysMap[exp.pubkey])
	}

	require.Len(t, keysMap, len(expectedData))
}
