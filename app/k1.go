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

package app

import (
	"crypto/ecdsa"
	"os"
	"path"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/obolnetwork/charon/app/errors"
)

// LoadOrCreatePrivKey returns a k1 (secp256k1) private key from the provided folder.
// If it doesn't exist, a new key is generated and stored and returned.
func LoadOrCreatePrivKey(dataDir string) (*ecdsa.PrivateKey, error) {
	keyPath := path.Join(dataDir, "p2pkey")

	key, err := crypto.LoadECDSA(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return newSavedPrivKey(keyPath)
	} else if err != nil {
		return nil, errors.Wrap(err, "load key")
	}

	return key, nil
}

// newSavedPrivKey generates a new key and saves the new node identity.
func newSavedPrivKey(keyPath string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, errors.Wrap(err, "mkdir")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, errors.Wrap(err, "gen key")
	}

	err = crypto.SaveECDSA(keyPath, key)
	if err != nil {
		return nil, errors.Wrap(err, "save key")
	}

	return key, nil
}
