// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
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
		password, err := randomHex64()
		if err != nil {
			return err
		}
		passwords = append(passwords, password)

		// TODO(gsora): needs to go away once we get rid of kryptology
		store, err := keystore.Encrypt(s.SecretShare, password, rand.Reader)
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
	var secrets []tblsv2.PrivateKey
	for _, s := range shares {
		secrets = append(secrets, s.SecretShare)
	}

	keysDir := path.Join(datadir, "/validator_keys")

	if err := os.Mkdir(keysDir, os.ModePerm); err != nil {
		return errors.Wrap(err, "mkdir /validator_keys")
	}

	return keystore.StoreKeys(secrets, keysDir)
}

// writeLock writes the lock file to disk.
//

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

// writeDepositData writes deposit data file to disk.
func writeDepositData(depositDatas []eth2p0.DepositData, network string, dataDir string) error {
	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(depositDatas, network)
	if err != nil {
		return err
	}

	// Write it to disk
	depositPath := path.Join(dataDir, "deposit-data.json")

	//nolint:gosec // File needs to be read-only for everybody
	err = os.WriteFile(depositPath, bytes, 0o444)
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

	return nil
}

// checkWrites writes sample files to check disk writes and removes sample files after verification.
func checkWrites(dataDir string) error {
	const checkBody = "delete me: dummy file used to check write permissions"
	for _, file := range []string{"cluster-lock.json", "deposit-data.json", "validator_keys/keystore-0.json"} {
		if filepath.Dir(file) != "." {
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

// validURI returns true if the input string is a valid HTTP/HTTPS URI.
func validURI(str string) bool {
	u, err := url.Parse(str)

	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
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
