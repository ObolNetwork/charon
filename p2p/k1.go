// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

// LoadPrivKey returns the secp256k1 key saved in the directory.
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
