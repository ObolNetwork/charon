// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

func TestStoreLoad(t *testing.T) {
	dir := t.TempDir()

	var secrets []tblsv2.PrivateKey
	for i := 0; i < 2; i++ {
		secret, err := tblsv2.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	actual, err := keystore.LoadKeys(dir)
	require.NoError(t, err)

	require.Equal(t, secrets, actual)
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
