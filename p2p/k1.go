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

package p2p

import (
	"crypto/ecdsa"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/obolnetwork/charon/app/errors"
)

func p2pKeyPath(datadir string) string {
	return path.Join(datadir, "p2pkey")
}

// LoadPrivKey returns the ecdsa k1 key saved in the directory.
func LoadPrivKey(dataDir string) (*ecdsa.PrivateKey, error) {
	key, err := crypto.LoadECDSA(p2pKeyPath(dataDir))
	if err != nil {
		return nil, errors.Wrap(err, "load key")
	}

	return key, nil
}

// NewSavedPrivKey generates a new ecdsa k1 key and saves it to the directory.
func NewSavedPrivKey(datadir string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(datadir, 0o755); err != nil {
		return nil, errors.Wrap(err, "mkdir")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, errors.Wrap(err, "gen key")
	}

	err = crypto.SaveECDSA(p2pKeyPath(datadir), key)
	if err != nil {
		return nil, errors.Wrap(err, "save key")
	}

	return key, nil
}
