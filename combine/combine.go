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
	"crypto/sha256"
	"encoding/json"
	"io"
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
//   - place the ".charon" directory in inputDir, renamed to another name
//
// Combine will create a new directory named after the public key of each validator key reconstructed, containing each
// keystore.
func Combine(ctx context.Context, inputDir string, force bool) error {
	log.Info(ctx, "Recombining key shares",
		z.Str("input_dir", inputDir),
	)

	lock, possibleKeyPaths, err := loadLockfile(inputDir)
	if err != nil {
		return errors.Wrap(err, "cannot open lock file")
	}

	privkeys := make(map[int][]tblsv2.PrivateKey)

	for _, pkp := range possibleKeyPaths {
		secrets, err := keystore.LoadKeys(pkp)
		if err != nil {
			return errors.Wrap(err, "cannot load keystore", z.Str("path", pkp))
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

		outPath := filepath.Join(inputDir, val.PublicKeyHex())
		if err := os.Mkdir(outPath, 0o755); err != nil {
			return errors.Wrap(err, "output directory creation", z.Int("validator_number", idx))
		}

		ksPath := filepath.Join(outPath, "keystore-0.json")
		_, err = os.Stat(ksPath)
		if err == nil && !force {
			return errors.New("refusing to overwrite existing private key", z.Int("validator_number", idx), z.Str("path", ksPath))
		}

		if err := keystore.StoreKeys([]tblsv2.PrivateKey{secret}, outPath); err != nil {
			return errors.Wrap(err, "cannot store keystore", z.Int("validator_number", idx))
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

// loadLockfile loads a lockfile from one of the charon directories contained in dir.
// It checks that all the directories containing a validator_keys subdirectory contain the same cluster_lock.json file.
// It returns the cluster.Lock read from the lock file, and a list of directories that possibly contains keys.
func loadLockfile(dir string) (cluster.Lock, []string, error) {
	root, err := os.ReadDir(dir)
	if err != nil {
		return cluster.Lock{}, nil, errors.Wrap(err, "can't read directory")
	}

	lfFound := false
	lastLockfileHash := [32]byte{}
	lfContent := []byte{}
	possibleValKeysDir := []string{}
	for _, sd := range root {
		if !sd.IsDir() {
			continue
		}

		// try opening the lock file
		lfPath := filepath.Join(dir, sd.Name(), "cluster-lock.json")
		b, err := os.Open(lfPath)
		if err != nil {
			continue
		}

		// does this directory contains a "validator_keys" directory? if yes continue and add it as a candidate
		vcdPath := filepath.Join(dir, sd.Name(), "validator_keys")
		_, err = os.ReadDir(vcdPath)
		if err != nil {
			continue
		}

		possibleValKeysDir = append(possibleValKeysDir, vcdPath)

		lfc, err := io.ReadAll(b)
		if err != nil {
			continue
		}

		lfHash := sha256.Sum256(lfc)

		if lastLockfileHash != [32]byte{} && lfHash != lastLockfileHash {
			return cluster.Lock{}, nil, errors.New("found different lockfile in node directory", z.Str("name", sd.Name()))
		}

		lastLockfileHash = lfHash
		lfContent = lfc
		lfFound = true
	}

	if !lfFound {
		return cluster.Lock{}, nil, errors.New("lock file not found")
	}

	var lock cluster.Lock
	if err := json.Unmarshal(lfContent, &lock); err != nil {
		return cluster.Lock{}, nil, errors.Wrap(err, "unmarshal lock file")
	}

	if err := lock.VerifyHashes(); err != nil {
		return cluster.Lock{}, nil, errors.Wrap(err, "cluster lock hash verification failed")
	}

	if err := lock.VerifySignatures(); err != nil {
		return cluster.Lock{}, nil, errors.Wrap(err, "cluster lock signature verification failed")
	}

	return lock, possibleValKeysDir, nil
}
