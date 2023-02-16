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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
)

// Combine combines validator keys contained in inputDir, and writes the original BLS12-381 private keys.
// Combine is validator-aware: it'll recombine all the validator keys listed in the "Validator" field of the lock file.
// To do so, the user must prepare inputDir as follows:
//   - place the lock file in input dir, named as "cluster-lock.json"
//   - create one directory for each operator, named after their ENR
//   - place in each of those directories the content of the "validator_keys" directory, contained in their Charon runtime
//     directory
func Combine(ctx context.Context, inputDir string, force bool) error {
	lfPath := filepath.Join(inputDir, "cluster-lock.json")
	b, err := os.Open(lfPath)
	if err != nil {
		return errors.Wrap(err, "read lock file")
	}

	var lock cluster.Lock
	if err := json.NewDecoder(b).Decode(&lock); err != nil {
		return errors.Wrap(err, "unmarshal lock file")
	}

	log.Info(ctx, "Recombining key shares",
		z.Int("validators_amount", lock.NumValidators),
		z.Str("lockfile", lfPath),
		z.Str("input_dir", inputDir),
	)

	privkeys := make(map[int][]tblsv2.PrivateKey)

	// check that for each ENR there's a directory and load the private keys
	for _, op := range lock.Definition.Operators {
		ep := filepath.Join(inputDir, op.ENR)
		_, err := os.Stat(ep)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return errors.Wrap(err, "enr directory error")
			}

			return errors.New("enr path not found", z.Str("path", ep))
		}

		secrets, err := keystore.LoadKeys(ep)
		if err != nil {
			return errors.Wrap(err, "cannot load keystore", z.Str("path", ep))
		}

		for idx, secret := range secrets {
			privkeys[idx] = append(privkeys[idx], secret)
		}
	}

	for idx, pkSet := range privkeys {
		log.Info(ctx, "Recombining key share", z.Int("validator_number", idx))
		shares, err := secretsToShares(lock, pkSet)
		if err != nil {
			return err
		}

		if len(shares) < lock.Threshold {
			return errors.New("insufficient number of keys", z.Int("validator_number", idx))
		}

		secret, err := tblsv2.RecoverSecret(shares, uint(len(lock.Operators)), uint(lock.Threshold))
		if err != nil {
			return errors.Wrap(err, "cannot recover shares", z.Int("validator_number", idx))
		}

		// require that the generated secret pubkey matches what's in the lockfile for the idx validator
		val := lock.Validators[idx]

		valPk, err := val.PublicKey()
		if err != nil {
			return errors.Wrap(err, "public key for validator from lockfile", z.Int("validator_number", idx))
		}

		genPubkey, err := tblsv2.SecretToPublicKey(secret)
		if err != nil {
			return errors.Wrap(err, "public key for validator from generated secret", z.Int("validator_number", idx))
		}

		if valPk != genPubkey {
			return errors.New("generated and lockfile public key for validator DO NOT match", z.Int("validator_number", idx))
		}

		outFile := filepath.Join(inputDir, fmt.Sprintf("%v.privkey", val.PublicKeyHex()))

		_, err = os.Stat(outFile)
		if err == nil && !force {
			return errors.New("refusing to overwrite existing private key", z.Int("validator_number", idx), z.Str("path", outFile))
		}

		if err := os.WriteFile(outFile, secret[:], 0o600); err != nil {
			return errors.Wrap(err, "cannot write private key file", z.Int("validator_number", idx), z.Str("path", outFile))
		}
	}

	return nil
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
