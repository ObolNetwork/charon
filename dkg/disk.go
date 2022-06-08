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
	"crypto/rand"
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
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
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

// checkWrites writes sample files to check disk writes and removes sample files after verification.
func checkWrites(dataDir string, def cluster.Definition) error {
	var shares []share
	sigs := make(map[core.PubKey]*bls_sig.Signature)
	for i := 0; i < def.NumValidators; i++ {
		tss, sks, err := tbls.GenerateTSS(def.Threshold, len(def.Operators), rand.Reader)
		if err != nil {
			return err
		}

		shares = append(shares, share{
			PubKey:       tss.PublicKey(),
			SecretShare:  sks[0],
			PublicShares: tss.PublicShares(),
		})

		pk, err := tblsconv.KeyToCore(tss.PublicKey())
		if err != nil {
			return err
		}

		sig, err := testutil.RandomBLSSignature()
		if err != nil {
			return err
		}

		sigs[pk] = sig
	}

	if err := writeDepositData(sigs, testutil.RandomETHAddress(), "prater", dataDir); err != nil {
		return err
	}

	if err := writeKeystores(dataDir, shares); err != nil {
		return err
	}

	lock := cluster.Lock{Definition: def}
	if err := writeLock(dataDir, lock); err != nil {
		return err
	}

	// Cleanup sample files
	if err := os.Remove(path.Join(dataDir, "deposit-data.json")); err != nil {
		return errors.Wrap(err, "remove sample deposit-data.json")
	}

	for i := 0; i < def.NumValidators; i++ {
		if err := os.Remove(path.Join(dataDir, fmt.Sprintf("keystore-%d.json", i))); err != nil {
			return errors.Wrap(err, fmt.Sprintf("remove sample keystore-%d.json", i))
		}

		if err := os.Remove(path.Join(dataDir, fmt.Sprintf("keystore-%d.txt", i))); err != nil {
			return errors.Wrap(err, fmt.Sprintf("remove sample keystore-%d.txt", i))
		}
	}

	if err := os.Remove(path.Join(dataDir, "cluster-lock.json")); err != nil {
		return errors.Wrap(err, "remove sample cluster-lock.json")
	}

	return nil
}
