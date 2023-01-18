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

package cmd

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

// KeymanagerReq represents the keymanager API request body for POST request. Refer: https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores
type KeymanagerReq struct {
	Keystores []keystore.Keystore `json:"keystores"`
	Passwords []string            `json:"passwords"`
}

// KeymanagerReqBody constructs a KeymanagerReq using the provided secrets and returns it.
func KeymanagerReqBody(secrets []*bls_sig.SecretKey) (KeymanagerReq, error) {
	var resp KeymanagerReq
	for _, secret := range secrets {
		password, err := randomHex32()
		if err != nil {
			return KeymanagerReq{}, err
		}

		store, err := keystore.Encrypt(secret, password, rand.Reader)
		if err != nil {
			return KeymanagerReq{}, err
		}

		resp.Keystores = append(resp.Keystores, store)
		resp.Passwords = append(resp.Passwords, password)
	}

	return resp, nil
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
