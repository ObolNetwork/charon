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

// Command combine combines threshold BLS secret shares into the group/root BLS secret.
// Note this only combines a single secret at a time.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

var (
	inputDir  = flag.String("input-dir", ".", "Directory containing the input keyshare to combine")
	outputDir = flag.String("output-dir", "output", "Directory to write the output combined keyshare")
	lockfile  = flag.String("lock-file", "cluster-lock.json", "Cluster lock file (required to infer share indexes)")
)

func main() {
	ctx := context.Background()
	err := run(ctx, *lockfile, *inputDir, *outputDir)
	if err != nil {
		log.Error(ctx, "Fatal run error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, lockfile, inputDir, outputDir string) error {
	log.Info(ctx, "Resharing key shares",
		z.Str("lockfile", lockfile),
		z.Str("input_dir", inputDir),
		z.Str("output_dir", outputDir),
	)

	b, err := os.ReadFile(lockfile)
	if err != nil {
		return errors.Wrap(err, "read lock file")
	}
	var lock cluster.Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return errors.Wrap(err, "unmarshal lock file")
	}

	secrets, err := keystore.LoadKeys(inputDir)
	if err != nil {
		return err
	}

	shares, err := secretsToShares(lock, secrets)
	if err != nil {
		return err
	}

	if len(shares) < lock.Threshold {
		return errors.New("insufficient number of keys")
	}

	secret, err := tbls.CombineSecrets(shares, lock.Threshold, len(lock.Operators))
	if err != nil {
		return err
	}

	return keystore.StoreKeys([]*bls_sig.SecretKey{secret}, outputDir)
}

//nolint:gocognit // It is just nested loops searching through all DVs to find the index of each share.
func secretsToShares(lock cluster.Lock, secrets []*bls_sig.SecretKey) ([]*bls_sig.SecretKeyShare, error) {
	n := len(lock.Operators)

	var resp []*bls_sig.SecretKeyShare
	for _, secret := range secrets {
		pubkey, err := secret.GetPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "pubkey from share")
		}

		expect, err := pubkey.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal pubkey")
		}

		var found bool
		for _, val := range lock.Validators {
			for i := 0; i < n; i++ {
				pubShare, err := val.PublicShare(i)
				if err != nil {
					return nil, errors.Wrap(err, "pubshare from lock")
				}

				actual, err := pubShare.MarshalBinary()
				if err != nil {
					return nil, errors.Wrap(err, "marshal pubshare")
				}

				if !bytes.Equal(expect, actual) {
					continue
				}

				secretBin, err := secret.MarshalBinary()
				if err != nil {
					return nil, errors.Wrap(err, "marshalling secret")
				}

				// ref: https://github.com/coinbase/kryptology/blob/71ffd4cbf01951cd0ee056fc7b45b13ffb178330/pkg/signatures/bls/bls_sig/lib.go#L26
				share := new(bls_sig.SecretKeyShare)
				if err := share.UnmarshalBinary(append(secretBin, byte(i+1))); err != nil {
					return nil, errors.Wrap(err, "unmarshalling share")
				}

				resp = append(resp, share)
				found = true

				break
			}

			if found {
				break
			}
		}

		if !found {
			return nil, errors.New("share not found in lock")
		}
	}

	return resp, nil
}
