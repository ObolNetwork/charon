// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// KeyFiles wraps a list of key files with convenience functions.
type KeyFiles []KeyFile

// Keys returns the private keys of the files.
func (k KeyFiles) Keys() []tbls.PrivateKey {
	var resp []tbls.PrivateKey
	for _, ks := range k {
		resp = append(resp, ks.PrivateKey)
	}

	return resp
}

// SequencedKeys returns the private keys in strict sequential file index order from 0 to N.
// If the indexes are unknown or not sequential or there are duplicates, an error is returned.
func (k KeyFiles) SequencedKeys() ([]tbls.PrivateKey, error) {
	resp := make([]tbls.PrivateKey, len(k))
	var zero tbls.PrivateKey
	for _, ks := range k {
		if !ks.HasIndex() {
			return nil, errors.New("unknown keystore index, filename not 'keystore-%d.json'", z.Str("filename", ks.Filename))
		}

		if ks.FileIndex < 0 || ks.FileIndex >= len(k) {
			return nil, errors.New("out of sequence keystore index",
				z.Int("index", ks.FileIndex), z.Str("filename", ks.Filename))
		}

		if resp[ks.FileIndex] != zero {
			return nil, errors.New("duplicate keystore index",
				z.Int("index", ks.FileIndex), z.Str("filename", ks.Filename))
		}

		resp[ks.FileIndex] = ks.PrivateKey
	}

	return resp, nil
}

// KeyFile represents the result of decrypting a keystore file and its private key.
type KeyFile struct {
	PrivateKey tbls.PrivateKey
	Filename   string
	FileIndex  int
}

// HasIndex returns true if the keystore file has an index.
func (k KeyFile) HasIndex() bool {
	return k.FileIndex != -1
}

// LoadFilesUnordered returns all decrypted keystore files stored in dir/keystore-*.json EIP-2335 Keystore files
// using password stored in dir/keystore-*.txt.
// The resulting keystore files are in random order.
func LoadFilesUnordered(dir string) (KeyFiles, error) {
	files, err := filepath.Glob(path.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "read files")
	}

	if len(files) == 0 {
		return nil, errors.New("no keys found")
	}

	workFunc := func(_ context.Context, filename string) (KeyFile, error) {
		b, err := os.ReadFile(filename)
		if err != nil {
			return KeyFile{}, errors.Wrap(err, "read file", z.Str("filename", filename))
		}

		var store Keystore
		if err := json.Unmarshal(b, &store); err != nil {
			return KeyFile{}, errors.Wrap(err, "unmarshal keystore", z.Str("filename", filename))
		}

		password, err := loadPassword(filename)
		if err != nil {
			return KeyFile{}, errors.Wrap(err, "load password", z.Str("filename", filename))
		}

		secret, err := decrypt(store, password)
		if err != nil {
			return KeyFile{}, errors.Wrap(err, "keystore decryption", z.Str("filename", filename))
		}

		idx, err := extractFileIndex(filename)
		if err != nil {
			return KeyFile{}, errors.Wrap(err, "extract file index", z.Str("filename", filename))
		}

		return KeyFile{
			PrivateKey: secret,
			Filename:   filename,
			FileIndex:  idx,
		}, nil
	}

	joinResults, cancel := forkjoin.NewWithInputs(
		context.Background(),
		workFunc,
		files,
		forkjoin.WithWorkers(loadStoreWorkers),
	)
	defer cancel()

	return joinResults.Flatten()
}

var extractor = regexp.MustCompile(`keystore-(?:insecure-)?([0-9]+).json`)

// extractFileIndex extracts the index from a keystore file name or returns -1
// if an index isn't present.
func extractFileIndex(filename string) (int, error) {
	if !extractor.MatchString(filename) {
		return -1, nil
	}

	matches := extractor.FindStringSubmatch(filename)
	if len(matches) != 2 {
		return 0, errors.New("unexpected regex error")
	}

	idx, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, errors.New("unexpected regex error")
	}

	return idx, nil
}
