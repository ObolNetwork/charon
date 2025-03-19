// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package combine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	erc1271 "github.com/obolnetwork/charon/app/eth1wrap/generated"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/eth2util"
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
func Combine(ctx context.Context, inputDir, outputDir string, force, noverify bool, executionEngineAddr string, testnetConfig eth2util.Network, opts ...func(*options)) error {
	o := options{
		keyStoreFunc: keystore.StoreKeys,
	}

	for _, opt := range opts {
		opt(&o)
	}

	// Check if custom testnet configuration is provided.
	if testnetConfig.IsNonZero() {
		// Add testnet config to supported networks.
		eth2util.AddTestNetwork(testnetConfig)
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

	cluster, possibleKeyPaths, err := loadManifest(ctx, inputDir, noverify, executionEngineAddr)
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

	for valIdx := range len(privkeys) {
		pkSet := privkeys[valIdx]

		if len(pkSet) < int(cluster.GetThreshold()) {
			return errors.New(
				"insufficient private key shares found for validator",
				z.Int("validator_index", valIdx),
				z.Int("expected", int(cluster.GetThreshold())),
				z.Int("actual", len(pkSet)),
			)
		}

		log.Info(ctx, "Recombining private key shares", z.Int("validator_index", valIdx))
		shares, err := shareIdxByPubkeys(cluster, pkSet, valIdx)
		if err != nil {
			return err
		}

		secret, err := tbls.RecoverSecret(shares, uint(len(cluster.GetOperators())), uint(cluster.GetThreshold()))
		if err != nil {
			return errors.Wrap(err, "cannot recover private key share", z.Int("validator_index", valIdx))
		}

		// require that the generated secret pubkey matches what's in the lockfile for the valIdx validator
		val := cluster.GetValidators()[valIdx]

		valPk, err := tblsconv.PubkeyFromBytes(val.GetPublicKey())
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

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return errors.Wrap(err, "ensure output directory exists", z.Str("output_dir", outputDir))
	}

	ksPath := filepath.Join(outputDir, "keystore-0.json")
	_, err = os.Stat(ksPath)
	if err == nil && !force {
		return errors.New("refusing to overwrite existing private key share", z.Str("path", ksPath))
	}

	if force {
		matches, err := filepath.Glob(filepath.Join(outputDir, "keystore-*.json"))
		if err != nil {
			return errors.Wrap(err, "can't match keystore files")
		}

		passMatches, err := filepath.Glob(filepath.Join(outputDir, "keystore-*.txt"))
		if err != nil {
			return errors.Wrap(err, "can't match keystore password files")
		}

		matches = append(matches, passMatches...)

		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				return errors.Wrap(err, "can't remove existing keystore file")
			}
		}
	}

	if err := o.keyStoreFunc(combinedKeys, outputDir); err != nil {
		return errors.Wrap(err, "cannot store keystore")
	}

	return nil
}

// shareIdxByPubkeys maps private keys to the valIndex validator public shares in the manifest file.
// It preserves the order as found in the validator public share slice.
func shareIdxByPubkeys(cluster *manifestpb.Cluster, secrets []tbls.PrivateKey, valIndex int) (map[int]tbls.PrivateKey, error) {
	pubkMap := make(map[tbls.PublicKey]int)

	for peerIdx := range len(cluster.GetValidators()[valIndex].GetPubShares()) {
		pubShareRaw := cluster.GetValidators()[valIndex].GetPubShares()[peerIdx]

		pubShare, err := tblsconv.PubkeyFromBytes(pubShareRaw)
		if err != nil {
			return nil, errors.Wrap(err, "pubkey from share")
		}

		// share indexes are 1-indexed
		pubkMap[pubShare] = peerIdx + 1
	}

	resp := make(map[int]tbls.PrivateKey)

	for _, secret := range secrets {
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
func WithInsecureKeysForT(_ *testing.T) func(*options) {
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
// It checks that all the directories containing a validator_keys subdirectory contain the same manifest file, or lock file.
// loadManifest gives precedence to the manifest file.
// loadManifest will fail if some of the directories contain a different set of manifest and lock file.
// For example, if 3 out of 4 directories contain both manifest and lock file, and the fourth only contains lock, loadManifest will return error.
// It returns the v1.Cluster read from the manifest, and a list of directories that possibly contains keys.
func loadManifest(ctx context.Context, dir string, noverify bool, executionEngineAddr string) (*manifestpb.Cluster, []string, error) {
	root, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read directory")
	}

	var (
		possibleValKeysDir []string
		lastCluster        *manifestpb.Cluster
	)

	for _, sd := range root {
		if !sd.IsDir() {
			continue
		}

		// does this directory contains a "validator_keys" directory? if yes continue and add it as a candidate
		vcdPath := filepath.Join(dir, sd.Name(), "validator_keys")
		_, err = os.ReadDir(vcdPath)
		if err != nil {
			continue
		}

		// try opening the lock file
		lockFile := filepath.Join(dir, sd.Name(), "cluster-lock.json")
		manifestFile := filepath.Join(dir, sd.Name(), "cluster-manifest.pb")

		cl, err := manifest.LoadCluster(manifestFile, lockFile, func(lock cluster.Lock) error {
			return verifyLock(ctx, lock, noverify, executionEngineAddr)
		})
		if err != nil {
			return nil, nil, errors.Wrap(err, "manifest load error", z.Str("name", sd.Name()))
		}

		if !noverify {
			if lastCluster != nil && !bytes.Equal(lastCluster.GetLatestMutationHash(), cl.GetLatestMutationHash()) {
				return nil, nil, errors.New("mismatching last mutation hash")
			}
		}

		possibleValKeysDir = append(possibleValKeysDir, vcdPath)

		lastCluster = cl
	}

	if lastCluster == nil {
		return nil, nil, errors.New("no manifest file found")
	}

	return lastCluster, possibleValKeysDir, nil
}

func verifyLock(ctx context.Context, lock cluster.Lock, noverify bool, executionEngineAddr string) error {
	if err := lock.VerifyHashes(); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
	}

	eth1Cl := eth1wrap.NewEthClientRunner(executionEngineAddr,
		func(ctx context.Context, url string) (eth1wrap.EthClient, error) {
			cl, err := ethclient.DialContext(ctx, url)
			if err != nil {
				return nil, errors.Wrap(err, "failed to connect to eth1 client")
			}

			return cl, nil
		},
		func(contractAddress string, cl eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
			addr := common.HexToAddress(contractAddress)
			erc1271, err := erc1271.NewErc1271(addr, cl)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create binding to ERC1271 contract")
			}

			return erc1271, nil
		},
	)
	if err := lock.VerifySignatures(eth1Cl); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return nil
}
