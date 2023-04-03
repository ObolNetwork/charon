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
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

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

		sm := make(map[int]tblsv2.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

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

func TestCombine(t *testing.T) {
	lock, _, shares := cluster.NewForT(t, 2, 3, 4, 0)

	// calculate expected public keys and secrets
	type expected struct {
		pubkey string
		secret string
	}

	var expectedData []expected

	for _, share := range shares {
		share := share

		sm := make(map[int]tblsv2.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tblsv2.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tblsv2.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

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

	keys, err := keystore.LoadKeys(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, key := range keys {
		pk, err := tblsv2.SecretToPublicKey(key)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", key)
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

		sm := make(map[int]tblsv2.PrivateKey)
		for idx, shareObj := range share {
			shareObj := shareObj
			sm[idx+1] = shareObj
		}

		complSecret, err := tblsv2.RecoverSecret(sm, 4, 3)
		require.NoError(t, err)

		complPubkey, err := tblsv2.SecretToPublicKey(complSecret)
		require.NoError(t, err)

		expectedData = append(expectedData, expected{
			pubkey: fmt.Sprintf("%#x", complPubkey),
			secret: fmt.Sprintf("%#x", complSecret),
		})
	}

	dir := t.TempDir()
	od := t.TempDir()

	// flatten secrets, each validator slice is unpacked in a flat structure
	var rawSecrets []tblsv2.PrivateKey
	for _, s := range shares {
		rawSecrets = append(rawSecrets, s...)
	}

	// for each ENR, create a slice of keys to hold
	// each set will be len(lock.Definition.Operators)
	secrets := make([][]tblsv2.PrivateKey, len(lock.Definition.Operators))

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

	keys, err := keystore.LoadKeys(od)
	require.NoError(t, err)

	keysMap := make(map[string]string)
	for _, key := range keys {
		pk, err := tblsv2.SecretToPublicKey(key)
		require.NoError(t, err)

		keysMap[fmt.Sprintf("%#x", pk)] = fmt.Sprintf("%#x", key)
	}

	for _, exp := range expectedData {
		require.Contains(t, keysMap, exp.pubkey)
		require.Equal(t, exp.secret, keysMap[exp.pubkey])
	}

	require.Len(t, keysMap, len(expectedData))
}
