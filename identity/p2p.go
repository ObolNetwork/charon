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

package identity

import (
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/internal/config"
)

// TODO(corver): Refactor this to just functions (not OO) like Create, Load, LoadOrCreate, remove Must.

// P2PStore stores the P2P identity key.
type P2PStore struct {
	KeyPath string
}

// DefaultP2P returns the DVC identity store at the default file path (<data_dir>/nodekey.json).
func DefaultP2P() P2PStore {
	dataDir := viper.GetString(config.KeyDataDir)
	return P2PStore{
		KeyPath: filepath.Join(dataDir, "nodekey"),
	}
}

// Create generates a new key and saves the new node identity.
func (s P2PStore) Create() (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(s.KeyPath), 0755); err != nil {
		return nil, err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	err = crypto.SaveECDSA(s.KeyPath, key)
	return key, err
}

// Load reads the existing node identity.
func (s P2PStore) Load() (*ecdsa.PrivateKey, error) {
	return crypto.LoadECDSA(s.KeyPath)
}

// Get retrieves the existing node identity or creates a new one.
func (s P2PStore) Get() (*ecdsa.PrivateKey, error) {
	key, err := s.Load()
	if errors.Is(err, os.ErrNotExist) {
		return s.Create()
	}
	return key, err
}

// MustGet returns the node's identity or terminates the program if an error occurs.
func (s P2PStore) MustGet() *ecdsa.PrivateKey {
	key, err := s.Get()
	if err != nil {
		zerologger.Fatal().Err(err).Msg("Failed to read node key")
	}
	return key
}
