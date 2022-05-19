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

package dkg

import (
	"encoding/json"
	"os"
	"path"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// loadDefinition returns the cluster definition from disk (or the test definition if configured).
func loadDefinition(conf Config) (cluster.Definition, error) {
	if conf.TestDef != nil {
		return *conf.TestDef, nil
	}

	buf, err := os.ReadFile(conf.DefFile)
	if err != nil {
		return cluster.Definition{}, errors.Wrap(err, "read definition")
	}

	var res cluster.Definition
	err = json.Unmarshal(buf, &res)
	if err != nil {
		return cluster.Definition{}, errors.Wrap(err, "unmarshal definition")
	}

	return res, nil
}

// writeKeystores writes the private share keystores to disk.
func writeKeystores(datadir string, shares []share) error {
	var secrets []*bls_sig.SecretKey
	for _, s := range shares {
		secret, err := tblsconv.ShareToSecret(s.SecretShare)
		if err != nil {
			return err
		}
		secrets = append(secrets, secret)
	}

	err := keystore.StoreKeys(secrets, datadir)
	if err != nil {
		return err
	}

	return nil
}

// writeLock writes the lock file to disk.
func writeLock(datadir string, lock cluster.Lock) error {
	b, err := json.MarshalIndent(lock, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	err = os.WriteFile(path.Join(datadir, "cluster-lock.json"), b, 0o444) // Read-only
	if err != nil {
		return errors.Wrap(err, "write lock")
	}

	return nil
}
