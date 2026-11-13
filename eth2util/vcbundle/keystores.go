// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"cmp"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/keystore"
)

var keystoreIndex = regexp.MustCompile(`^keystore-(?:insecure-)?([0-9]+)\.json$`)

// keystoreFile is a keystore and its password file in the validator keys directory.
type keystoreFile struct {
	// Pubkey is the keystore's public key, lowercase with a 0x prefix.
	Pubkey       string
	KeystorePath string
	PasswordPath string
	// Index is the index in the file name, -1 without one.
	Index int
}

// listKeystores returns the keystore-*.json files in dir with their password files, by index. The keystores
// are not decrypted, only their public key is read.
func listKeystores(dir string) ([]keystoreFile, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "list keystores")
	}

	if len(paths) == 0 {
		return nil, errors.New("no keystores found", z.Str("dir", dir))
	}

	var (
		resp []keystoreFile
		seen = make(map[string]bool)
	)

	for _, path := range paths {
		file, err := readKeystoreFile(path)
		if err != nil {
			return nil, err
		}

		if seen[file.Pubkey] {
			return nil, errors.New("duplicate keystore public key", z.Str("pubkey", file.Pubkey), z.Str("path", path))
		}

		seen[file.Pubkey] = true
		resp = append(resp, file)
	}

	// Files without an index sort after indexed ones, by name.
	slices.SortFunc(resp, func(a, b keystoreFile) int {
		switch {
		case a.Index == b.Index:
			return strings.Compare(a.KeystorePath, b.KeystorePath)
		case a.Index == -1:
			return 1
		case b.Index == -1:
			return -1
		default:
			return cmp.Compare(a.Index, b.Index)
		}
	})

	return resp, nil
}

// readKeystoreFile returns the keystore at path, checking its password file exists.
func readKeystoreFile(path string) (keystoreFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return keystoreFile{}, errors.Wrap(err, "read keystore", z.Str("path", path))
	}

	var store keystore.Keystore

	err = json.Unmarshal(b, &store)
	if err != nil {
		return keystoreFile{}, errors.Wrap(err, "unmarshal keystore", z.Str("path", path))
	}

	if store.Pubkey == "" {
		return keystoreFile{}, errors.New("keystore without public key", z.Str("path", path))
	}

	passwordPath := strings.TrimSuffix(path, ".json") + ".txt"

	_, err = os.Stat(passwordPath)
	if errors.Is(err, os.ErrNotExist) {
		return keystoreFile{}, errors.New("keystore password file not found", z.Str("path", passwordPath))
	} else if err != nil {
		return keystoreFile{}, errors.Wrap(err, "stat keystore password file", z.Str("path", passwordPath))
	}

	index := -1

	matches := keystoreIndex.FindStringSubmatch(filepath.Base(path))
	if matches != nil {
		index, err = strconv.Atoi(matches[1])
		if err != nil {
			return keystoreFile{}, errors.Wrap(err, "parse keystore index", z.Str("path", path))
		}
	}

	return keystoreFile{
		Pubkey:       "0x" + strings.TrimPrefix(strings.ToLower(store.Pubkey), "0x"),
		KeystorePath: path,
		PasswordPath: passwordPath,
		Index:        index,
	}, nil
}

// keystoreFiles returns the keystores and passwords in the client's layout. Lighthouse reads them in place.
func keystoreFiles(ctx context.Context, client Client, keysDir string, keystores []keystoreFile) ([]bundleFile, error) {
	// paths returns the keystore and password paths of a keystore in the bundle.
	var paths func(k keystoreFile) (keystorePath, passwordPath string)

	flat := func(k keystoreFile) (string, string) {
		return filepath.Join("keystores", filepath.Base(k.KeystorePath)), filepath.Join("keystores", filepath.Base(k.PasswordPath))
	}

	switch client {
	case Teku:
		log.Info(ctx, "Keystores copied, teku reads the keystore and password pairs as they are", z.Str("dir", "keystores"), z.Int("keystores", len(keystores)))

		paths = flat
	case Prysm:
		log.Info(ctx, "Keystores copied for prysm's wallet import", z.Str("dir", "keystores"), z.Int("keystores", len(keystores)))

		paths = flat
	case Lodestar:
		log.Info(ctx, "Keystores written in lodestar's layout", z.Str("keystores_dir", "keystores"), z.Str("secrets_dir", "secrets"), z.Int("keystores", len(keystores)))

		paths = func(k keystoreFile) (string, string) {
			return filepath.Join("keystores", k.Pubkey, "voting-keystore.json"), filepath.Join("secrets", k.Pubkey)
		}
	case Nimbus:
		log.Info(ctx, "Keystores written in nimbus's layout", z.Str("keystores_dir", "validators"), z.Str("secrets_dir", "secrets"), z.Int("keystores", len(keystores)))

		paths = func(k keystoreFile) (string, string) {
			return filepath.Join("validators", k.Pubkey, "keystore.json"), filepath.Join("secrets", k.Pubkey)
		}
	case Lighthouse:
		dir, err := filepath.Abs(keysDir)
		if err != nil {
			return nil, errors.Wrap(err, "absolute validator keys path")
		}

		log.Info(ctx, "Keystores read in place by lighthouse, its definitions point at them", z.Str("dir", dir))

		return nil, nil
	default:
		return nil, errors.New("unknown validator client", z.Str("client", string(client)))
	}

	var files []bundleFile

	for _, k := range keystores {
		keystorePath, passwordPath := paths(k)

		keystore, err := os.ReadFile(k.KeystorePath)
		if err != nil {
			return nil, errors.Wrap(err, "read keystore", z.Str("path", k.KeystorePath))
		}

		password, err := os.ReadFile(k.PasswordPath)
		if err != nil {
			return nil, errors.Wrap(err, "read keystore password", z.Str("path", k.PasswordPath))
		}

		files = append(files,
			bundleFile{Path: keystorePath, Data: keystore, Mode: secretMode},
			bundleFile{Path: passwordPath, Data: password, Mode: secretMode},
		)
	}

	return files, nil
}
