// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package combine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// Combine combines validator private key shares contained in inputDir, and writes the original BLS12-381 private keys.
// Combine is cluster-aware: it'll recombine all the validator keys listed in the "Validator" field of the lock file.
// To do so place all the cluster nodes' ".charon" directories in inputDir renaming each.
// Note all nodes directories must be preset and all validator private key shares must be present.
//
// Combine will create a new directory named after "outputDir", which will contain Keystore files.
func Combine(ctx context.Context, inputDir, outputDir string, force bool, opts ...func(*options)) error {
	o := options{
		keyStoreFunc: keystore.StoreKeys,
	}

	for _, opt := range opts {
		opt(&o)
	}

	if !filepath.IsAbs(outputDir) {
		fp, err := filepath.Abs(outputDir)
		if err != nil {
			return errors.Wrap(err, "cannot make full path from relative output path")
		}

		outputDir = fp
	}

	if !filepath.IsAbs(inputDir) {
		fp, err := filepath.Abs(inputDir)
		if err != nil {
			return errors.Wrap(err, "cannot make full path from relative input path")
		}

		inputDir = fp
	}

	log.Info(ctx, "Recombining private key shares",
		z.Str("input_dir", inputDir),
		z.Str("output_dir", outputDir),
	)

	lock, possibleKeyPaths, err := loadLockfile(inputDir)
	if err != nil {
		return errors.Wrap(err, "cannot open lock file")
	}

	privkeys := make(map[int][]tbls.PrivateKey)

	for _, pkp := range possibleKeyPaths {
		log.Info(ctx, "Loading keystore", z.Str("path", pkp))

		keyFiles, err := keystore.LoadFilesUnordered(pkp)
		if err != nil {
			return errors.Wrap(err, "cannot load private key share", z.Str("path", pkp))
		}

		secrets, err := keyFiles.SequencedKeys()
		if err != nil {
			return errors.Wrap(err, "order private key shares")
		}

		for idx, secret := range secrets {
			privkeys[idx] = append(privkeys[idx], secret)
		}
	}

	var combinedKeys []tbls.PrivateKey

	for valIdx := 0; valIdx < len(privkeys); valIdx++ {
		pkSet := privkeys[valIdx]

		if len(pkSet) != len(lock.Operators) {
			return errors.New(
				"not all private key shares found for validator",
				z.Int("validator_index", valIdx),
				z.Int("expected", len(lock.Operators)),
				z.Int("actual", len(pkSet)),
			)
		}

		log.Info(ctx, "Recombining private key shares", z.Int("validator_index", valIdx))
		shares, err := shareIdxByPubkeys(lock, pkSet, valIdx)
		if err != nil {
			return err
		}

		secret, err := tbls.RecoverSecret(shares, uint(len(lock.Operators)), uint(lock.Threshold))
		if err != nil {
			return errors.Wrap(err, "cannot recover private key share", z.Int("validator_index", valIdx))
		}

		// require that the generated secret pubkey matches what's in the lockfile for the valIdx validator
		val := lock.Validators[valIdx]

		valPk, err := val.PublicKey()
		if err != nil {
			return errors.Wrap(err, "public key for validator from lockfile", z.Int("validator_index", valIdx))
		}

		genPubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return errors.Wrap(err, "public key for validator from generated secret", z.Int("validator_index", valIdx))
		}

		if valPk != genPubkey {
			return errors.New("unexpected resulting combined validator public key",
				z.Int("validator_index", valIdx), z.Hex("actual", genPubkey[:]), z.Hex("expected", valPk[:]))
		}

		combinedKeys = append(combinedKeys, secret)
	}

	ksPath := filepath.Join(outputDir, "keystore-0.json")
	_, err = os.Stat(ksPath)
	if err == nil && !force {
		return errors.New("refusing to overwrite existing private key share", z.Str("path", ksPath))
	}

	if err := o.keyStoreFunc(combinedKeys, outputDir); err != nil {
		return errors.Wrap(err, "cannot store keystore")
	}

	return nil
}

// shareIdxByPubkeys maps private keys to the valIndex validator public shares in the lock file.
// It preserves the order as found in the validator public share slice.
func shareIdxByPubkeys(lock cluster.Lock, secrets []tbls.PrivateKey, valIndex int) (map[int]tbls.PrivateKey, error) {
	pubkMap := make(map[tbls.PublicKey]int)

	for peerIdx := 0; peerIdx < len(lock.Validators[valIndex].PubShares); peerIdx++ {
		peerIdx := peerIdx
		pubShare, err := lock.Validators[valIndex].PublicShare(peerIdx)
		if err != nil {
			return nil, errors.Wrap(err, "pubshare from lock")
		}

		// share indexes are 1-indexed
		pubkMap[pubShare] = peerIdx + 1
	}

	resp := make(map[int]tbls.PrivateKey)

	for _, secret := range secrets {
		secret := secret

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "pubkey from share")
		}

		shareIdx, pubkFound := pubkMap[pubkey]
		if !pubkFound {
			return nil, errors.New("can't find secret key share",
				z.Int("validator_index", valIndex),
			)
		}

		resp[shareIdx] = secret
	}

	return resp, nil
}

// WithInsecureKeysForT is a functional option for Combine that will use the insecure keystore.StoreKeysInsecure function.
func WithInsecureKeysForT(*testing.T) func(*options) {
	return func(o *options) {
		o.keyStoreFunc = func(secrets []tbls.PrivateKey, dir string) error {
			return keystore.StoreKeysInsecure(secrets, dir, keystore.ConfirmInsecureKeys)
		}
	}
}

type options struct {
	keyStoreFunc func(secrets []tbls.PrivateKey, dir string) error
}

// loadLockfile loads a lockfile from one of the charon directories contained in dir.
// It checks that all the directories containing a validator_keys subdirectory contain the same cluster_lock.json file.
// It returns the cluster.Lock read from the lock file, and a list of directories that possibly contains keys.
func loadLockfile(dir string) (cluster.Lock, []string, error) {
	root, err := os.ReadDir(dir)
	if err != nil {
		return cluster.Lock{}, nil, errors.Wrap(err, "can't read directory")
	}

	var (
		lfFound            bool
		lastLockfileHash   [32]byte
		lfContent          []byte
		possibleValKeysDir []string
	)

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
