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
	"os"
	"path"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
)

// KeyPath returns the charon-enr-private-key path relative to the data dir.
func KeyPath(datadir string) string {
	return path.Join(datadir, "charon-enr-private-key")
}

// LoadPrivKey returns the k1 key saved in the directory.
func LoadPrivKey(dataDir string) (*k1.PrivateKey, error) {
	key, err := k1util.Load(KeyPath(dataDir))
	if err != nil {
		return nil, errors.Wrap(err, "load priv key")
	}

	return key, nil
}

// NewSavedPrivKey generates a new ecdsa k1 key and saves it to the directory.
func NewSavedPrivKey(datadir string) (*k1.PrivateKey, error) {
	if err := os.MkdirAll(datadir, 0o755); err != nil {
		return nil, errors.Wrap(err, "mkdir")
	}

	key, err := k1.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "gen key")
	}

	err = k1util.Save(key, KeyPath(datadir))
	if err != nil {
		return nil, errors.Wrap(err, "save key")
	}

	return key, nil
}
