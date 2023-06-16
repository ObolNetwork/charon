// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore_test

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
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

	keyFiles, err := keystore.LoadFilesUnordered(dir)
	require.NoError(t, err)

	actual, err := keyFiles.SequencedKeys()
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

	expect := make(map[tbls.PrivateKey]bool)
	var secrets []tbls.PrivateKey
	for i := 0; i < len(filenames); i++ {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
		expect[secret] = true
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

	keyFiles, err := keystore.LoadFilesUnordered(dir)
	require.NoError(t, err)

	require.Len(t, keyFiles, len(expect))

	for _, keyFile := range keyFiles {
		require.True(t, expect[keyFile.PrivateKey])
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

	keyFiles, err := keystore.LoadFilesUnordered(dir)
	require.NoError(t, err)

	actual, err := keyFiles.SequencedKeys()
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

	oldPath = filepath.Join(dir, "keystore-insecure-1.txt")
	newPath = filepath.Join(dir, "keystore-insecure-42.txt")
	require.NoError(t, os.Rename(oldPath, newPath))

	keyFiles, err := keystore.LoadFilesUnordered(dir)
	require.NoError(t, err)

	actual, err := keyFiles.SequencedKeys()
	require.ErrorContains(t, err, "out of sequence keystore index")

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

	keyFiles, err := keystore.LoadFilesUnordered(dir)
	require.NoError(t, err)

	actual, err := keyFiles.SequencedKeys()
	require.ErrorContains(t, err, "unknown keystore index, filename not 'keystore-%d.json'")
	require.Empty(t, actual)
}

func TestLoadEmpty(t *testing.T) {
	_, err := keystore.LoadFilesUnordered(".")
	require.Error(t, err)
}

func TestLoadScrypt(t *testing.T) {
	keyfiles, err := keystore.LoadFilesUnordered("testdata")
	require.NoError(t, err)

	require.Len(t, keyfiles, 1)

	require.Equal(t, "10b16fc552aa607fa1399027f7b86ab789077e470b5653b338693dc2dde02468", fmt.Sprintf("%x", keyfiles[0].PrivateKey))
}

func TestSequencedKeys(t *testing.T) {
	tests := []struct {
		name     string
		suffixes []string
		ok       bool
	}{
		{
			name:     "happy 1",
			suffixes: []string{"0"},
			ok:       true,
		},
		{
			name:     "happy 2",
			suffixes: []string{"0", "1"},
			ok:       true,
		},
		{
			name:     "happy 4",
			suffixes: []string{"0", "1", "2", "3"},
			ok:       true,
		},
		{
			name:     "missing 0",
			suffixes: []string{"1", "2", "3"},
			ok:       false,
		},
		{
			name:     "missing 2",
			suffixes: []string{"0", "1", "3"},
			ok:       false,
		},
		{
			name: "happy 20",
			suffixes: []string{
				"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
				"11", "12", "13", "14", "15", "16", "17", "18", "19",
			},
			ok: true,
		},
		{
			name:     "non-numeric",
			suffixes: []string{"0", "1", "foo"},
			ok:       false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			var expected []tbls.PrivateKey
			for _, suffix := range test.suffixes {
				target := filepath.Join(dir, fmt.Sprintf("keystore-%s.json", suffix))
				secret := storeNewKeyForT(t, target)
				expected = append(expected, secret)
			}

			keyFiles, err := keystore.LoadFilesUnordered(dir)
			require.NoError(t, err)

			actual, err := keyFiles.SequencedKeys()
			if !test.ok {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}

// storeNewKeyForT generates a new key and stores it in the given target filename
// it also stores the corresponding txt password next to it.
// It also returns the generated key.
func storeNewKeyForT(t *testing.T, target string) tbls.PrivateKey {
	t.Helper()
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	dir := t.TempDir()
	err = keystore.StoreKeysInsecure([]tbls.PrivateKey{secret}, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	err = os.Rename(path.Join(dir, "keystore-insecure-0.json"), target)
	require.NoError(t, err)

	err = os.Rename(path.Join(dir, "keystore-insecure-0.txt"), strings.ReplaceAll(target, ".json", ".txt"))
	require.NoError(t, err)

	return secret
}
