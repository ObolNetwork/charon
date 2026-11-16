// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"

	"github.com/google/uuid"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// PrysmWalletDir is the directory of Prysm's wallet, which Prysm reads with --wallet-dir.
const PrysmWalletDir = "prysm-wallet"

var (
	// prysmWalletPath is where Prysm's local keymanager reads its accounts.
	prysmWalletPath = filepath.Join(PrysmWalletDir, "direct", "accounts", "all-accounts.keystore.json")
	// prysmWalletPasswordPath is the wallet password file Prysm reads from the wallet directory without a flag.
	prysmWalletPasswordPath = filepath.Join(PrysmWalletDir, "walletpassword.txt")
)

// prysmAccounts is the decrypted content of a Prysm wallet, base64 encoded by encoding/json.
type prysmAccounts struct {
	PrivateKeys [][]byte `json:"private_keys"`
	PublicKeys  [][]byte `json:"public_keys"`
}

// prysmWallet is a Prysm wallet's accounts file.
type prysmWallet struct {
	Crypto  map[string]any `json:"crypto"`
	ID      string         `json:"uuid"`
	Version uint           `json:"version"`
	Name    string         `json:"name"`
}

// prysmWalletFiles returns a Prysm wallet of the decrypted keystores, encrypted with a new random password written
// in the wallet directory. Each keystore's secret key is checked against its public key.
func prysmWalletFiles(keysDir string, keystores []keystoreFile) ([]bundleFile, error) {
	keyFiles, err := keystore.LoadFilesUnordered(keysDir)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt keystores")
	}

	secrets := make(map[string]tbls.PrivateKey, len(keyFiles))
	for _, f := range keyFiles {
		secrets[f.Filename] = f.PrivateKey
	}

	var accounts prysmAccounts

	for _, k := range keystores {
		secret, ok := secrets[k.KeystorePath]
		if !ok {
			return nil, errors.New("keystore not decrypted", z.Str("path", k.KeystorePath))
		}

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "derive public key", z.Str("path", k.KeystorePath))
		}

		if "0x"+hex.EncodeToString(pubkey[:]) != k.Pubkey {
			return nil, errors.New("keystore public key does not match its secret key", z.Str("path", k.KeystorePath))
		}

		accounts.PrivateKeys = append(accounts.PrivateKeys, secret[:])
		accounts.PublicKeys = append(accounts.PublicKeys, pubkey[:])
	}

	plaintext, err := json.Marshal(accounts) //nolint:gosec // Encrypted into the wallet below.
	if err != nil {
		return nil, errors.Wrap(err, "marshal prysm accounts")
	}

	var random [32]byte

	_, err = rand.Read(random[:])
	if err != nil {
		return nil, errors.Wrap(err, "generate wallet password")
	}

	password := hex.EncodeToString(random[:])

	encryptor := keystorev4.New()

	crypto, err := encryptor.Encrypt(plaintext, password)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt prysm wallet")
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "generate wallet uuid")
	}

	wallet, err := marshalJSON(prysmWallet{Crypto: crypto, ID: id.String(), Version: encryptor.Version(), Name: encryptor.Name()})
	if err != nil {
		return nil, err
	}

	return []bundleFile{
		{Path: prysmWalletPath, Data: wallet, Mode: secretMode},
		{Path: prysmWalletPasswordPath, Data: []byte(password), Mode: secretMode},
	}, nil
}
