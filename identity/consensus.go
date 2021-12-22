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

// Package identity stores the ECDSA P2P key and the BLS12-381 DV consensus key.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	crypto2 "github.com/obolnetwork/charon/crypto"
	"github.com/obolnetwork/charon/internal/config"
	"github.com/spf13/viper"
)

// ConsensusStore stores a single DVC consensus key using a keystore and password file.
type ConsensusStore struct {
	KeystorePath string
	PasswordPath string
}

// ConsensusKey wraps a BLS12-381 keypair.
type ConsensusKey struct {
	PrivKey kyber.Scalar
	PubKey  *bls12381.KyberG1
}

// DefaultConsensus returns the DVC identity store at the default file path (<data_dir>/nodekey.json).
func DefaultConsensus() ConsensusStore {
	dataDir := viper.GetString(config.KeyDataDir)
	return ConsensusStore{
		KeystorePath: filepath.Join(dataDir, "dvkey.json"),
		PasswordPath: filepath.Join(dataDir, "dv_password.txt"),
	}
}

// Password reads the node password or creates a new random password if none exists.
func (s ConsensusStore) Password() (password string, err error) {
	password, err = crypto2.ReadPlaintextPassword(s.PasswordPath)
	if errors.Is(err, os.ErrNotExist) {
		return s.createNewPassword()
	}
	return
}

func (s ConsensusStore) createNewPassword() (string, error) {
	// Create new random 128-bit password.
	var pwdBytes [32]byte
	_, err := rand.Read(pwdBytes[:])
	if err != nil {
		return "", err
	}
	password := hex.EncodeToString(pwdBytes[:])
	// Zero stack buffer.
	for i := range pwdBytes {
		pwdBytes[i] = 0
	}
	// Write back to file.
	err = crypto2.WritePlaintextPassword(s.PasswordPath, false, password)
	if err != nil {
		return "", err
	}
	return password, nil
}

// Create generates a new key and saves the new node identity.
//
// TODO Make sure the created key can't ever be used for validators.
func (s ConsensusStore) Create() (*ConsensusKey, error) {
	password, err := s.Password()
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %w", err)
	}
	key, privKey, pubKey, err := crypto2.NewBLSKeystore(password)
	if err != nil {
		return nil, err
	}
	if err := key.Save(s.KeystorePath); err != nil {
		return nil, err
	}
	return &ConsensusKey{
		PrivKey: privKey,
		PubKey:  pubKey.(*bls12381.KyberG1),
	}, nil
}

// Load reads the existing node identity.
func (s ConsensusStore) Load() (*ConsensusKey, error) {
	password, err := s.Password()
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %w", err)
	}
	key, err := crypto2.LoadKeystore(s.KeystorePath)
	if err != nil {
		return nil, err
	}
	priv, pub, err := key.BLSKeyPair(password)
	if err != nil {
		return nil, err
	}
	return &ConsensusKey{
		PrivKey: priv,
		PubKey:  pub.(*bls12381.KyberG1),
	}, nil
}

// Get retrieves the existing node identity or creates a new one.
func (s ConsensusStore) Get() (*ConsensusKey, error) {
	key, err := s.Load()
	if errors.Is(err, os.ErrNotExist) {
		return s.Create()
	}
	return key, err
}
