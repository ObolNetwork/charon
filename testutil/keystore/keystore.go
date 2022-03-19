// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package keystore provides functions to store and load simnet private keys
// to/from EIP 2335 compatible keystore files with empty passwords.
package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// StoreSimnetKeys stores the secrets in dir/keystore-simnet-%d.json files with empty passwords.
func StoreSimnetKeys(secrets []*bls_sig.SecretKey, dir string) error {
	for i, secret := range secrets {
		store, err := encrypt(secret, "", rand.Reader)
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(store, "", " ")
		if err != nil {
			return errors.Wrap(err, "marshal keystore")
		}

		filename := path.Join(dir, fmt.Sprintf("keystore-simnet-%d.json", i))
		if err := os.WriteFile(filename, b, 0o600); err != nil {
			return errors.Wrap(err, "write keystore")
		}
	}

	return nil
}

// LoadSimnetKeys returns all secrets stores in dir/keystore-*.json files using empty passwords.
func LoadSimnetKeys(dir string) ([]*bls_sig.SecretKey, error) {
	files, err := filepath.Glob(path.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "read files")
	}

	var resp []*bls_sig.SecretKey
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, errors.Wrap(err, "read file")
		}

		var store keystore
		if err := json.Unmarshal(b, &store); err != nil {
			return nil, errors.Wrap(err, "unmarshal keystore")
		}

		secret, err := decrypt(store, "")
		if err != nil {
			return nil, err
		}

		resp = append(resp, secret)
	}

	return resp, nil
}

// keystore json file representation as a Go struct.
type keystore struct {
	Crypto  map[string]interface{} `json:"crypto"`
	ID      string                 `json:"uuid"`
	Pubkey  string                 `json:"pubkey"`
	Version uint                   `json:"version"`
	Name    string                 `json:"name"`
}

// encrypt returns the secret as an encrypted keystore.
func encrypt(secret *bls_sig.SecretKey, password string, random io.Reader) (keystore, error) {
	secretBytes, err := tblsconv.SecretToBytes(secret)
	if err != nil {
		return keystore{}, err
	}

	pubKey, err := secret.GetPublicKey()
	if err != nil {
		return keystore{}, errors.Wrap(err, "get pubkey")
	}
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return keystore{}, errors.Wrap(err, "marshal pubkey")
	}

	encryptor := keystorev4.New(keystorev4.WithCipher("scrypt"))
	fields, err := encryptor.Encrypt(secretBytes, password)
	if err != nil {
		return keystore{}, errors.Wrap(err, "encrypt keystore")
	}

	return keystore{
		Crypto:  fields,
		ID:      uuid(random),
		Version: encryptor.Version(),
		Pubkey:  hex.EncodeToString(pubKeyBytes),
		Name:    encryptor.Name(),
	}, nil
}

// decrypt returns the secret from the encrypted (empty password) keystore.
func decrypt(store keystore, password string) (*bls_sig.SecretKey, error) {
	encryptor := keystorev4.New(keystorev4.WithCipher("scrypt"))
	secretBytes, err := encryptor.Decrypt(store.Crypto, password)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt keystore")
	}

	return tblsconv.SecretFromBytes(secretBytes)
}

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
