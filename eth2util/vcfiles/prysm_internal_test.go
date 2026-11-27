// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcfiles

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

func TestPrysmWalletFiles(t *testing.T) {
	dir := t.TempDir()
	secrets := writeEncryptedTestKeystores(t, dir, 2)

	keystores, err := listKeystores(dir)
	require.NoError(t, err)

	files, err := prysmWalletFiles(dir, keystores)
	require.NoError(t, err)
	require.Len(t, files, 2)

	walletFile, passwordFile := files[0], files[1]
	require.Equal(t, "prysm-wallet/direct/accounts/all-accounts.keystore.json", walletFile.Path)
	require.Equal(t, "prysm-wallet/walletpassword.txt", passwordFile.Path)
	require.Equal(t, os.FileMode(secretMode), walletFile.Mode)
	require.Equal(t, os.FileMode(secretMode), passwordFile.Mode)
	require.Len(t, passwordFile.Data, 64)

	var wallet struct {
		Crypto  map[string]any `json:"crypto"`
		ID      string         `json:"uuid"`
		Version uint           `json:"version"`
		Name    string         `json:"name"`
	}
	require.NoError(t, json.Unmarshal(walletFile.Data, &wallet))
	require.Equal(t, "keystore", wallet.Name)
	require.Equal(t, uint(4), wallet.Version)
	require.NotEmpty(t, wallet.ID)

	plaintext, err := keystorev4.New().Decrypt(wallet.Crypto, string(passwordFile.Data))
	require.NoError(t, err)

	var accounts struct {
		PrivateKeys [][]byte `json:"private_keys"`
		PublicKeys  [][]byte `json:"public_keys"`
	}
	require.NoError(t, json.Unmarshal(plaintext, &accounts))
	require.Len(t, accounts.PrivateKeys, 2)
	require.Len(t, accounts.PublicKeys, 2)

	for i, secret := range secrets {
		pubkey, err := tbls.SecretToPublicKey(secret)
		require.NoError(t, err)
		require.Equal(t, secret[:], accounts.PrivateKeys[i])
		require.Equal(t, pubkey[:], accounts.PublicKeys[i])
	}
}

func TestPrysmWalletFilesErrors(t *testing.T) {
	t.Run("wrong password", func(t *testing.T) {
		dir := t.TempDir()
		writeEncryptedTestKeystores(t, dir, 1)
		overwriteTestFile(t, filepath.Join(dir, "keystore-insecure-0.txt"), []byte("wrong"))

		keystores, err := listKeystores(dir)
		require.NoError(t, err)

		_, err = prysmWalletFiles(dir, keystores)
		require.ErrorContains(t, err, "keystore decryption")
		require.NotContains(t, err.Error(), "wrong")
	})

	t.Run("public key mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeEncryptedTestKeystores(t, dir, 1)

		path := filepath.Join(dir, "keystore-insecure-0.json")
		b, err := os.ReadFile(path)
		require.NoError(t, err)

		var store keystore.Keystore
		require.NoError(t, json.Unmarshal(b, &store))
		store.Pubkey = hex.EncodeToString(make([]byte, 48))
		b, err = json.Marshal(store)
		require.NoError(t, err)
		overwriteTestFile(t, path, b)

		keystores, err := listKeystores(dir)
		require.NoError(t, err)

		_, err = prysmWalletFiles(dir, keystores)
		require.ErrorContains(t, err, "keystore public key does not match its secret key")
	})
}

// writeEncryptedTestKeystores writes n keystores of new secrets with their password files and returns the secrets.
func writeEncryptedTestKeystores(t *testing.T, dir string, n int) []tbls.PrivateKey {
	t.Helper()

	var secrets []tbls.PrivateKey

	for range n {
		secret, err := tbls.GenerateSecretKey()
		require.NoError(t, err)

		secrets = append(secrets, secret)
	}

	require.NoError(t, keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys))

	return secrets
}

// overwriteTestFile replaces the content of the read-only file keystore.StoreKeysInsecure wrote.
func overwriteTestFile(t *testing.T, path string, data []byte) {
	t.Helper()

	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, data, 0o600))
}
