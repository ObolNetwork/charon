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

package p2p

import (
	"crypto/ecdsa"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/obolnetwork/charon/app/errors"
)

// KeyPath returns the p2pkey path relative to the data dir.
func KeyPath(datadir string) string {
	return path.Join(datadir, "p2pkey")
}

// LoadPrivKey returns the ecdsa k1 key saved in the directory.
func LoadPrivKey(dataDir string) (*ecdsa.PrivateKey, error) {
	key, err := crypto.LoadECDSA(KeyPath(dataDir))
	if err != nil {
		return nil, errors.Wrap(err, "load priv key")
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

	err = crypto.SaveECDSA(KeyPath(datadir), key)
	if err != nil {
		return nil, errors.Wrap(err, "save key")
	}

	return key, nil
}
