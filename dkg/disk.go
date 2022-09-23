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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/deposit"
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
		def, err = fetchDefinition(ctx, conf.DefFile)
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

// fetchDefinition fetches cluster definition file from a remote URI.
func fetchDefinition(ctx context.Context, url string) (cluster.Definition, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return cluster.Definition{}, errors.Wrap(err, "create http request")
	}

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return cluster.Definition{}, errors.Wrap(err, "fetch file")
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return cluster.Definition{}, errors.Wrap(err, "read response body")
	}

	var res cluster.Definition
	if err := json.Unmarshal(buf, &res); err != nil {
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

	if err := os.Mkdir(path.Join(datadir, "/validator_keys"), os.ModePerm); err != nil {
		return errors.Wrap(err, "mkdir /validator_keys")
	}

	if err := keystore.StoreKeys(secrets, path.Join(datadir, "/validator_keys")); err != nil {
		return errors.Wrap(err, "store keystores")
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
func writeDepositData(aggSigs map[core.PubKey]*bls_sig.Signature, withdrawalAddr []byte, network string, dataDir string) error {
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

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(aggSigsEth2, checksumAddr(withdrawalAddr), network)
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
