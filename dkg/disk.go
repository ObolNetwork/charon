// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// loadDefinition returns the cluster definition from disk or an HTTP URL. It returns the test definition if configured.
func loadDefinition(ctx context.Context, conf Config, eth1Cl eth1wrap.EthClientRunner) (cluster.Definition, error) {
	if conf.TestConfig.Def != nil {
		return *conf.TestConfig.Def, nil
	}

	// Fetch definition from URI or disk

	parsedURL, err := url.ParseRequestURI(conf.DefFile)

	var def cluster.Definition

	if err == nil && parsedURL.Host != "" {
		if !strings.HasPrefix(parsedURL.Scheme, "https") {
			log.Warn(ctx, "Definition file URL does not use https protocol", nil, z.Str("addr", conf.DefFile))
		}

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

	if err := def.VerifySignatures(eth1Cl); err != nil && !conf.NoVerify {
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

	if err := deposit.VerifyDepositAmounts(def.DepositAmounts, def.Compounding); err != nil {
		return cluster.Definition{}, err
	}

	return def, nil
}

// writeKeysToKeymanager writes validator private keyshares for the node to the provided keymanager address.
func writeKeysToKeymanager(ctx context.Context, keymanagerURL, authToken string, shares []share) error {
	var (
		keystores []keystore.Keystore
		passwords []string
	)

	for _, s := range shares {
		password, err := randomHex64()
		if err != nil {
			return err
		}

		passwords = append(passwords, password)

		store, err := keystore.Encrypt(s.SecretShare, password, rand.Reader)
		if err != nil {
			return err
		}

		keystores = append(keystores, store)
	}

	cl := keymanager.New(keymanagerURL, authToken)

	err := cl.ImportKeystores(ctx, keystores, passwords)
	if err != nil {
		return err
	}

	return nil
}

// writeKeysToDisk writes validator private keyshares for the node to disk.
func writeKeysToDisk(conf Config, shares []share) error {
	var secrets []tbls.PrivateKey
	for _, s := range shares {
		secrets = append(secrets, s.SecretShare)
	}

	keysDir, err := cluster.CreateValidatorKeysDir(conf.DataDir)
	if err != nil {
		return err
	}

	storeKeysFunc := keystore.StoreKeys
	if conf.TestConfig.StoreKeysFunc != nil {
		storeKeysFunc = conf.TestConfig.StoreKeysFunc
	}

	return storeKeysFunc(secrets, keysDir)
}

// writeLock writes the lock file to disk.
func writeLock(datadir string, lock cluster.Lock) error {
	b, err := json.MarshalIndent(lock, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	//nolint:gosec // File needs to be read-only for everybody
	err = os.WriteFile(path.Join(datadir, "cluster-lock.json"), b, 0o444) // Read-only
	if err != nil {
		return errors.Wrap(err, "write lock")
	}

	return nil
}

func checkClearDataDir(dataDir string) error {
	// if dataDir is a file, return error
	info, err := os.Stat(dataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrap(err, "error while retrieving data directory info", z.Str("data-dir", dataDir))
	} else if err != nil && errors.Is(err, fs.ErrNotExist) {
		return errors.New("data directory doesn't exist, cannot continue", z.Str("data-dir", dataDir))
	} else if err == nil && !info.IsDir() {
		return errors.New("data directory already exists and is a file, cannot continue", z.Str("data-dir", dataDir))
	}

	// get a listing of dataDir
	dirContent, err := os.ReadDir(dataDir)
	if err != nil {
		return errors.Wrap(err, "cannot list contents of data directory", z.Str("data-dir", dataDir))
	}

	disallowedEntities := map[string]struct{}{
		"validator_keys":    {},
		"cluster-lock.json": {},
	}

	necessaryEntities := map[string]bool{
		"charon-enr-private-key": false,
	}

	for _, entity := range dirContent {
		isDepositData := strings.HasPrefix(entity.Name(), "deposit-data")

		if _, disallowed := disallowedEntities[entity.Name()]; disallowed || isDepositData {
			return errors.New("data directory not clean, cannot continue", z.Str("disallowed_entity", entity.Name()), z.Str("data-dir", dataDir))
		}

		if _, ok := necessaryEntities[entity.Name()]; ok {
			necessaryEntities[entity.Name()] = true
		}
	}

	for fn, neFound := range necessaryEntities {
		if !neFound {
			return errors.New("missing required files, cannot continue", z.Str("file_name", fn), z.Str("data-dir", dataDir))
		}
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

		//nolint:gosec // File needs to be read-only for everybody
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

// randomHex64 returns a random 64 character hex string. It uses crypto/rand.
func randomHex64() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}
