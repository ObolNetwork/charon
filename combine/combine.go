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

package combine

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

// Combine combines validator keys contained in inputDir, and writes the original BLS12-381 private key in outputDir.
func Combine(ctx context.Context, lockfile, inputDir, outputDir string) error {
	log.Info(ctx, "Recombining key shares",
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

	secret, err := tblsv2.RecoverSecret(shares, uint(len(lock.Operators)), uint(lock.Threshold))
	if err != nil {
		return err
	}

	_, err = os.Stat(outputDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return errors.Wrap(err, "output directory error")
		}

		if err := os.Mkdir(outputDir, 0o755); err != nil {
			return errors.Wrap(err, "can't create output directory")
		}
	}

	return keystore.StoreKeys([]tblsv2.PrivateKey{secret}, outputDir)
}

func secretsToShares(lock cluster.Lock, secrets []tblsv2.PrivateKey) (map[int]tblsv2.PrivateKey, error) {
	n := len(lock.Operators)

	resp := make(map[int]tblsv2.PrivateKey)
	for idx, secret := range secrets {
		pubkey, err := tblsv2.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "pubkey from share")
		}

		var found bool
		for _, val := range lock.Validators {
			for i := 0; i < n; i++ {
				pubShare, err := val.PublicShare(i)
				if err != nil {
					return nil, errors.Wrap(err, "pubshare from lock")
				}

				if !bytes.Equal(pubkey[:], pubShare[:]) {
					continue
				}

				resp[idx+1] = secret
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
