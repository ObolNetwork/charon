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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// loadDefinition returns the cluster definition from disk or an HTTP URL. It returns the test definition if configured.
func loadDefinition(ctx context.Context, conf Config) (cluster.Definition, error) {
	if conf.TestDef != nil {
		return *conf.TestDef, nil
	}

	// Fetch definition from URI or disk

	var def cluster.Definition
	if validURI(conf.DefFile) {
		var err error
		def, err = cluster.FetchDefinition(ctx, conf.DefFile)
		if err != nil {
			return cluster.Definition{}, errors.Wrap(err, "read definition")
		}

		log.Info(ctx, "Cluster definition downloaded from URL", z.Str("URL", conf.DefFile),
			z.Str("definition_hash", fmt.Sprintf("%#x", def.DefinitionHash)))
	} else {
		buf, err := os.ReadFile(conf.DefFile)
		if err != nil {
			return cluster.Definition{}, errors.Wrap(err, "read definition")
		}

		if err = json.Unmarshal(buf, &def); err != nil {
			return cluster.Definition{}, errors.Wrap(err, "unmarshal definition")
		}

		log.Info(ctx, "Cluster definition loaded from disk", z.Str("path", conf.DefFile),
			z.Str("definition_hash", fmt.Sprintf("%#x", def.DefinitionHash)))
	}

	// Verify

	if err := def.VerifyHashes(); err != nil && !conf.NoVerify {
		return cluster.Definition{}, errors.Wrap(err, "cluster definition hashes verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster definition hashes verification due to --no-verify flag", err)
	}

	if err := def.VerifySignatures(); err != nil && !conf.NoVerify {
		return cluster.Definition{}, errors.Wrap(err, "cluster definition signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && conf.NoVerify {
		log.Warn(ctx, "Ignoring failed cluster definition signature verification due to --no-verify flag", err)
	}

	// Ensure we have a definition hash in case of no-verify.
	if len(def.DefinitionHash) == 0 {
		var err error
		def, err = def.SetDefinitionHashes()
		if err != nil {
			return cluster.Definition{}, err
		}
	}

	return def, nil
}

// writeKeysToKeymanager writes validator private keyshares for the node to the provided keymanager address.
func writeKeysToKeymanager(ctx context.Context, keymanagerURL string, shares []share) error {
	var (
		keystores []keystore.Keystore
		passwords []string
	)

	for _, s := range shares {
		password, err := randomHex32()
		if err != nil {
			return err
		}
		passwords = append(passwords, password)

		secret, err := tblsconv.ShareToSecret(s.SecretShare)
		if err != nil {
			return err
		}

		store, err := keystore.Encrypt(secret, password, rand.Reader)
		if err != nil {
			return err
		}
		keystores = append(keystores, store)
	}

	cl := keymanager.New(keymanagerURL)
	err := cl.ImportKeystores(ctx, keystores, passwords)
	if err != nil {
		return err
	}

	return nil
}

// writeKeysToDisk writes validator private keyshares for the node to disk.
func writeKeysToDisk(datadir string, shares []share) error {
	var secrets []*bls_sig.SecretKey
	for _, s := range shares {
		secret, err := tblsconv.ShareToSecret(s.SecretShare)
		if err != nil {
			return err
		}
		secrets = append(secrets, secret)
	}

	keysDir := path.Join(datadir, "/validator_keys")

	if err := os.Mkdir(keysDir, os.ModePerm); err != nil {
		return errors.Wrap(err, "mkdir /validator_keys")
	}

	return keystore.StoreKeys(secrets, keysDir)
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
			return err
		}

		pubkey, err := tblsconv.KeyToETH2(blsPubKey)
		if err != nil {
			return err
		}

		sigEth2 := tblsconv.SigToETH2(sig)
		aggSigsEth2[pubkey] = sigEth2
	}

	withdrawalAddr, err := eth2util.ChecksumAddress(withdrawalAddr)
	if err != nil {
		return err
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
func checkWrites(dataDir string) error {
	const checkBody = "delete me: dummy file used to check write permissions"
	for _, file := range []string{"cluster-lock.json", "deposit-data.json", "validator_keys/keystore-0.json"} {
		if filepath.Dir(file) != "" {
			if err := os.MkdirAll(filepath.Join(dataDir, filepath.Dir(file)), 0o777); err != nil {
				return errors.Wrap(err, "mkdir check writes", z.Str("dir", filepath.Dir(file)))
			}
		}

		if err := os.WriteFile(filepath.Join(dataDir, file), []byte(checkBody), 0o444); err != nil {
			return errors.Wrap(err, "write file check writes", z.Str("file", file))
		}

		if err := os.Remove(filepath.Join(dataDir, file)); err != nil {
			return errors.Wrap(err, "remove file check writes", z.Str("file", file))
		}

		if filepath.Dir(file) != "." {
			if err := os.RemoveAll(filepath.Join(dataDir, filepath.Dir(file))); err != nil {
				return errors.Wrap(err, "remove dir check writes", z.Str("dir", filepath.Dir(file)))
			}
		}
	}

	return nil
}

// validURI returns true if the input string is a valid HTTP/HTTPS URI.
func validURI(str string) bool {
	u, err := url.Parse(str)

	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// randomHex32 returns a random 32 character hex string. It uses crypto/rand.
func randomHex32() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}
