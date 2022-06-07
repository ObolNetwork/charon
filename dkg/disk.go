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
	"fmt"
	"os"
	"path"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/deposit"
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

// writeDepositData writes deposit data file to disk.
func writeDepositData(aggSigs map[core.PubKey]*bls_sig.Signature, withdrawalAddr string, network string, dataDir string) error {
	// Create deposit message signatures
	aggSigsEth2 := make(map[eth2p0.BLSPubKey]eth2p0.BLSSignature)
	for pk, sig := range aggSigs {
		blsPubKey, err := tblsconv.KeyFromCore(pk)
		if err != nil {
			return nil
		}

		pubkey, err := tblsconv.KeyToETH2(blsPubKey)
		if err != nil {
			return err
		}

		sigEth2 := tblsconv.SigToETH2(sig)
		aggSigsEth2[pubkey] = sigEth2
	}

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(aggSigsEth2, withdrawalAddr, network)
	if err != nil {
		return err
	}

	// Write it to disk
	depositPath := path.Join(dataDir, "deposit-data.json")
	err = os.WriteFile(depositPath, bytes, 0o444) // read-only
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

	return nil
}

// fileExists returns error if keystores, cluster-lock and deposit-data already exists in given dataDir.
func fileExists(dataDir string, vals int) error {
	for i := 0; i < vals; i++ {
		_, err := os.Stat(path.Join(dataDir, fmt.Sprintf("keystore-%d.json", i)))
		if err == nil {
			return errors.Wrap(err, fmt.Sprintf("keystore-%d.json already exists", i))
		}
	}

	_, err := os.Stat(path.Join(dataDir, "cluster-lock.json"))
	if err == nil {
		return errors.Wrap(err, fmt.Sprintf("cluster-lock.json already exists"))
	}

	_, err = os.Stat(path.Join(dataDir, "deposit-data.json"))
	if err == nil {
		return errors.Wrap(err, fmt.Sprintf("deposit-data.json already exists"))
	}

	return nil
}
