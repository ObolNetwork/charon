// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package combine

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Combine combines validator private key shares contained in inputDir, and writes the original BLS12-381 private keys.
// Combine is cluster-aware: it'll recombine all the validator keys listed in the "Validator" field of the lock file.
// To do so place all the cluster nodes' ".charon" directories in inputDir renaming each.
// Note all nodes directories must be preset and all validator private key shares must be present.
//
// Combine will create a new directory named after "outputDir", which will contain Keystore files.
func Combine(ctx context.Context, inputDir, outputDir string, force, noverify bool, opts ...func(*options)) error {
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

	manifestContent, possibleKeyPaths, err := loadManifest(ctx, inputDir, noverify)
	if err != nil {
		return errors.Wrap(err, "cannot open manifest file")
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

		if len(pkSet) != len(manifestContent.Operators) {
			return errors.New(
				"not all private key shares found for validator",
				z.Int("validator_index", valIdx),
				z.Int("expected", len(manifestContent.Operators)),
				z.Int("actual", len(pkSet)),
			)
		}

		log.Info(ctx, "Recombining private key shares", z.Int("validator_index", valIdx))
		shares, err := shareIdxByPubkeys(manifestContent, pkSet, valIdx)
		if err != nil {
			return err
		}

		secret, err := tbls.RecoverSecret(shares, uint(len(manifestContent.Operators)), uint(manifestContent.Threshold))
		if err != nil {
			return errors.Wrap(err, "cannot recover private key share", z.Int("validator_index", valIdx))
		}

		// require that the generated secret pubkey matches what's in the lockfile for the valIdx validator
		val := manifestContent.Validators[valIdx]

		valPk, err := tblsconv.PubkeyFromBytes(val.PublicKey)
		if err != nil {
			return errors.Wrap(err, "public key for validator from manifest", z.Int("validator_index", valIdx))
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

// shareIdxByPubkeys maps private keys to the valIndex validator public shares in the manifest file.
// It preserves the order as found in the validator public share slice.
func shareIdxByPubkeys(manifest *manifestpb.Cluster, secrets []tbls.PrivateKey, valIndex int) (map[int]tbls.PrivateKey, error) {
	pubkMap := make(map[tbls.PublicKey]int)

	for peerIdx := 0; peerIdx < len(manifest.Validators[valIndex].PubShares); peerIdx++ {
		peerIdx := peerIdx
		pubShareRaw := manifest.Validators[valIndex].GetPubShares()[peerIdx]

		pubShare, err := tblsconv.PubkeyFromBytes(pubShareRaw)
		if err != nil {
			return nil, errors.Wrap(err, "pubkey from share")
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

// loadManifest loads a cluster manifest from one of the charon directories contained in dir.
// It checks that all the directories containing a validator_keys subdirectory contain the same cluster_lock.json file.
// It returns the v1.Cluster read from the manifest, and a list of directories that possibly contains keys.
func loadManifest(ctx context.Context, dir string, noverify bool) (*manifestpb.Cluster, []string, error) {
	// TODO(gsora): this function only deals with lock files, waiting for #2334 to be solved.

	root, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read directory")
	}

	var (
		possibleValKeysDir []string
		lastManifest       *manifestpb.Cluster
		lastValHash        [32]byte
	)

	for _, sd := range root {
		if !sd.IsDir() {
			continue
		}

		// try opening the lock file
		lfPath := filepath.Join(dir, sd.Name(), "cluster-lock.json")

		cl, err := manifest.Load(lfPath, func(lock cluster.Lock) error {
			return verifyLock(ctx, lock, noverify)
		})
		if err != nil {
			return nil, nil, errors.Wrap(err, "manifest load error", z.Str("name", sd.Name()))
		}

		// does this directory contains a "validator_keys" directory? if yes continue and add it as a candidate
		vcdPath := filepath.Join(dir, sd.Name(), "validator_keys")
		_, err = os.ReadDir(vcdPath)
		if err != nil {
			continue
		}

		possibleValKeysDir = append(possibleValKeysDir, vcdPath)

		data, err := proto.Marshal(&manifestpb.ValidatorList{Validators: cl.Validators})
		if err != nil {
			return nil, nil, errors.New("manifest contains wrong validator data", z.Str("name", sd.Name()))
		}

		valHash := sha256.Sum256(data)

		if lastValHash != [32]byte{} && valHash != lastValHash {
			return nil, nil, errors.New("found different validator data in node directory", z.Str("name", sd.Name()))
		}

		lastManifest = cl
		lastValHash = valHash
	}

	if lastManifest == nil {
		return nil, nil, errors.New("no manifest file found")
	}

	return lastManifest, possibleValKeysDir, nil
}

func verifyLock(ctx context.Context, lock cluster.Lock, noverify bool) error {
	if err := lock.VerifyHashes(); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return nil
}
