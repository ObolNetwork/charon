// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

func TestStoreLoad(t *testing.T) {
	dir := t.TempDir()

	var secrets []tbls.PrivateKey
	for i := 0; i < 2; i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	actual, err := keystore.LoadKeys(dir)
	require.NoError(t, err)

	require.Equal(t, secrets, actual)
}

func TestStoreLoadNonCharonNames(t *testing.T) {
	dir := t.TempDir()

	filenames := []string{
		"keystore-bar-1",
		"keystore-bar-2",
		"keystore-bar-10",
		"keystore-foo",
	}

	sort.Strings(filenames)

	var secrets []tbls.PrivateKey

	for i := 0; i < len(filenames); i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	// rename according to filenames slice
	for idx := 0; idx < len(filenames); idx++ {
		oldPath := filepath.Join(dir, fmt.Sprintf("keystore-insecure-%d.json", idx))
		newPath := filepath.Join(dir, fmt.Sprintf("%s.json", filenames[idx]))
		require.NoError(t, os.Rename(oldPath, newPath))

		oldPath = filepath.Join(dir, fmt.Sprintf("keystore-insecure-%d.txt", idx))
		newPath = filepath.Join(dir, fmt.Sprintf("%s.txt", filenames[idx]))
		require.NoError(t, os.Rename(oldPath, newPath))
	}

	actual, err := keystore.LoadKeys(dir)
	require.NoError(t, err)

	for idx, genpk := range secrets {
		require.Equal(t, genpk, actual[idx])
	}
}

func TestStoreLoadKeysAll(t *testing.T) {
	dir := t.TempDir()

	var secrets []tbls.PrivateKey
	for i := 0; i < 2; i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	actual, err := keystore.LoadKeysSequential(dir)
	require.NoError(t, err)

	require.Equal(t, secrets, actual)
}

func TestStoreLoadKeysAllNonSequentialIdx(t *testing.T) {
	dir := t.TempDir()

	var secrets []tbls.PrivateKey
	for i := 0; i < 2; i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	oldPath := filepath.Join(dir, "keystore-insecure-1.json")
	newPath := filepath.Join(dir, "keystore-insecure-42.json")
	require.NoError(t, os.Rename(oldPath, newPath))

	actual, err := keystore.LoadKeysSequential(dir)
	require.ErrorContains(t, err, "keyfile sorting: indices are non sequential")

	require.Empty(t, actual)
}

func TestStoreLoadSequentialNonCharonNames(t *testing.T) {
	dir := t.TempDir()

	filenames := []string{
		"keystore-bar-1",
		"keystore-bar-2",
		"keystore-bar-10",
		"keystore-foo",
	}

	sort.Strings(filenames)

	var secrets []tbls.PrivateKey

	for i := 0; i < len(filenames); i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	// rename according to filenames slice
	for idx := 0; idx < len(filenames); idx++ {
		oldPath := filepath.Join(dir, fmt.Sprintf("keystore-insecure-%d.json", idx))
		newPath := filepath.Join(dir, fmt.Sprintf("%s.json", filenames[idx]))
		require.NoError(t, os.Rename(oldPath, newPath))

		oldPath = filepath.Join(dir, fmt.Sprintf("keystore-insecure-%d.txt", idx))
		newPath = filepath.Join(dir, fmt.Sprintf("%s.txt", filenames[idx]))
		require.NoError(t, os.Rename(oldPath, newPath))
	}

	actual, err := keystore.LoadKeysSequential(dir)
	require.ErrorContains(t, err, "keystore filenames do not match expected pattern 'keystore-%d.json' or 'keystore-insecure-%d.json'")
	require.Empty(t, actual)
}

func TestLoadEmpty(t *testing.T) {
	_, err := keystore.LoadKeys(".")
	require.Error(t, err)
}

func TestLoadScrypt(t *testing.T) {
	secrets, err := keystore.LoadKeys("testdata")
	require.NoError(t, err)

	require.Len(t, secrets, 1)

	require.Equal(t, "10b16fc552aa607fa1399027f7b86ab789077e470b5653b338693dc2dde02468", fmt.Sprintf("%x", secrets[0]))
}

func TestStoreLoadSingleValidatorNotStartingFromOne(t *testing.T) {
	dir := t.TempDir()

	var secrets []tbls.PrivateKey
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	secrets = append(secrets, secret)

	err = keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	require.NoError(
		t,
		os.Rename(
			filepath.Join(dir, "keystore-insecure-0.json"),
			filepath.Join(dir, "keystore-insecure-42.json"),
		),
	)

	require.NoError(
		t,
		os.Rename(
			filepath.Join(dir, "keystore-insecure-0.txt"),
			filepath.Join(dir, "keystore-insecure-42.txt"),
		),
	)

	actual, err := keystore.LoadKeysSequential(dir)
	require.ErrorContains(t, err, "keystore indices must start from zero")

	require.Empty(t, actual)
}
