// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package keystore provides functions to store and load private keys
// to/from EIP 2335 (https://eips.ethereum.org/EIPS/eip-2335) compatible keystore files. Passwords are
// expected/created in files with same identical names as the keystores, except with txt extension.
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
	"strings"
	"testing"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const insecurePower = 4

type confirmInsecure struct{}

// ConfirmInsecureKeys is syntactic sugar to highlight the security implications of insecure keys.
var ConfirmInsecureKeys confirmInsecure

// StoreKeysInsecure stores the secrets in dir/keystore-insecure-%d.json EIP 2335 keystore files
// with new random passwords stored in dir/keystore-insecure-%d.txt.
//
// 🚨 The keystores are insecure and should only be used for testing large validator sets
// as it speeds up encryption and decryption at the cost of security.
func StoreKeysInsecure(secrets []*bls_sig.SecretKey, dir string, _ confirmInsecure) error {
	return storeKeysInternal(secrets, dir, "keystore-insecure-%d.json",
		keystorev4.WithCost(new(testing.T), insecurePower))
}

// StoreKeys stores the secrets in dir/keystore-%d.json EIP 2335 keystore files
// with new random passwords stored in dir/keystore-%d.txt.
func StoreKeys(secrets []*bls_sig.SecretKey, dir string) error {
	return storeKeysInternal(secrets, dir, "keystore-%d.json")
}

func storeKeysInternal(secrets []*bls_sig.SecretKey, dir string, filenameFmt string, opts ...keystorev4.Option) error {
	for i, secret := range secrets {
		password, err := randomHex32()
		if err != nil {
			return err
		}

		store, err := encrypt(secret, password, rand.Reader, opts...)
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(store, "", " ")
		if err != nil {
			return errors.Wrap(err, "marshal keystore")
		}

		filename := path.Join(dir, fmt.Sprintf(filenameFmt, i))
		if err := os.WriteFile(filename, b, 0o444); err != nil {
			return errors.Wrap(err, "write keystore")
		}

		if err := storePassword(filename, password); err != nil {
			return err
		}
	}

	return nil
}

// LoadKeys returns all secrets stored in dir/keystore-*.json 2335 keystore files
// using password stored in dir/keystore-*.txt.
func LoadKeys(dir string) ([]*bls_sig.SecretKey, error) {
	files, err := filepath.Glob(path.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "read files")
	}

	if len(files) == 0 {
		return nil, errors.New("no keys found")
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

		password, err := loadPassword(f)
		if err != nil {
			return nil, err
		}

		secret, err := decrypt(store, password)
		if err != nil {
			return nil, err
		}

		resp = append(resp, secret)
	}

	return resp, nil
}

// keystore json file representation as a Go struct.
type keystore struct {
	Crypto      map[string]interface{} `json:"crypto"`
	Description string                 `json:"description"`
	Pubkey      string                 `json:"pubkey"`
	Path        string                 `json:"path"`
	ID          string                 `json:"uuid"`
	Version     uint                   `json:"version"`
}

// encrypt returns the secret as an encrypted keystore using pbkdf2 cipher.
func encrypt(secret *bls_sig.SecretKey, password string, random io.Reader,
	opts ...keystorev4.Option,
) (keystore, error) {
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

	encryptor := keystorev4.New(opts...)
	fields, err := encryptor.Encrypt(secretBytes, password)
	if err != nil {
		return keystore{}, errors.Wrap(err, "encrypt keystore")
	}

	return keystore{
		Crypto:      fields,
		Description: "", // optional field to help explain the purpose and identify a particular keystore in a user-friendly manner.
		Pubkey:      hex.EncodeToString(pubKeyBytes),
		Path:        "m/12381/3600/0/0/0", // https://eips.ethereum.org/EIPS/eip-2334
		ID:          uuid(random),
		Version:     encryptor.Version(),
	}, nil
}

// decrypt returns the secret from the encrypted (empty password) keystore.
func decrypt(store keystore, password string) (*bls_sig.SecretKey, error) {
	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(store.Crypto, password)
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

// loadPassword loads a keystore password from the keystore's associated password file.
func loadPassword(keyFile string) (string, error) {
	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		return "", errors.New("keystore password file not found " + keyFile)
	}

	passwordFile := strings.Replace(keyFile, ".json", ".txt", 1)
	b, err := os.ReadFile(passwordFile)
	if err != nil {
		return "", errors.Wrap(err, "read password file")
	}

	return string(b), nil
}

// storePassword stores a password to the keystore's associated password file.
func storePassword(keyFile string, password string) error {
	passwordFile := strings.Replace(keyFile, ".json", ".txt", 1)

	err := os.WriteFile(passwordFile, []byte(password), 0o400)
	if err != nil {
		return errors.Wrap(err, "write password file")
	}

	return nil
}

// randomHex32 returns a random 32 character hex string.
func randomHex32() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}
