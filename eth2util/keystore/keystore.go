// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package keystore provides functions to store and load private keys
// to/from EIP 2335 (https://eips.ethereum.org/EIPS/eip-2335) compatible Keystore files. Passwords are
// expected/created in files with same identical names as the keystores, except with txt extension.
package keystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// insecureCost decreases the cipher key cost from the default 18 to 4 which speeds up
	// encryption and decryption at the cost of security.
	insecureCost = 4

	// loadStoreWorkers is the amount of workers to use when loading/storing keys concurrently.
	loadStoreWorkers = 64
)

type confirmInsecure struct{}

// ConfirmInsecureKeys is syntactic sugar to highlight the security implications of insecure keys.
var ConfirmInsecureKeys confirmInsecure

// StoreKeysInsecure stores the secrets in dir/keystore-insecure-%d.json EIP 2335 Keystore files
// with new random passwords stored in dir/keystore-insecure-%d.txt.
//
// 🚨 The keystores are insecure and should only be used for testing large validator sets
// as it speeds up encryption and decryption at the cost of security.
func StoreKeysInsecure(secrets []tbls.PrivateKey, dir string, _ confirmInsecure) error {
	return storeKeysInternal(secrets, dir, "keystore-insecure-%d.json",
		keystorev4.WithCost(new(testing.T), insecureCost))
}

// StoreKeys stores the secrets in dir/keystore-%d.json EIP 2335 Keystore files
// with new random passwords stored in dir/Keystore-%d.txt.
func StoreKeys(secrets []tbls.PrivateKey, dir string) error {
	return storeKeysInternal(secrets, dir, "keystore-%d.json")
}

func storeKeysInternal(secrets []tbls.PrivateKey, dir string, filenameFmt string, opts ...keystorev4.Option) error {
	type data struct {
		index  int
		secret tbls.PrivateKey
	}

	fork, join, cancel := forkjoin.New(
		context.Background(),
		func(ctx context.Context, d data) (any, error) {
			filename := path.Join(dir, fmt.Sprintf(filenameFmt, d.index))

			password, err := randomHex32()
			if err != nil {
				return nil, err
			}

			store, err := Encrypt(d.secret, password, rand.Reader, opts...)
			if err != nil {
				return nil, errors.Wrap(err, "encryption error", z.Str("filename", filename))
			}

			b, err := json.MarshalIndent(store, "", " ")
			if err != nil {
				return nil, errors.Wrap(err, "marshal keystore", z.Str("filename", filename))
			}

			//nolint:gosec // File needs to be read-only for everybody
			if err := os.WriteFile(filename, b, 0o444); err != nil {
				return nil, errors.Wrap(err, "write keystore", z.Str("filename", filename))
			}

			if err := storePassword(filename, password); err != nil {
				return nil, errors.Wrap(err, "store password", z.Str("filename", filename))
			}

			return nil, nil
		},
		forkjoin.WithWorkers(loadStoreWorkers),
	)

	defer cancel()

	for i, secret := range secrets {
		i := i
		secret := secret
		d := data{
			index:  i,
			secret: secret,
		}

		fork(d)
	}

	results := join()
	_, err := results.Flatten()

	return err
}

// loadFiles loads EIP-2335 keystore files from dir, with the given glob.
// If sortKeyfiles is not nil, it will run it passing the file list as input, and
// its output will be used as the source of file names to read keystores from.
func loadFiles(dir string, sortKeyfiles func([]string) ([]string, error)) ([]tbls.PrivateKey, error) {
	files, err := filepath.Glob(path.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "read files")
	}

	if len(files) == 0 {
		return nil, errors.New("no keys found")
	}

	if sortKeyfiles != nil {
		files, err = sortKeyfiles(files)
		if err != nil {
			return nil, errors.Wrap(err, "keyfile sorting")
		}
	}

	type openFileInput struct {
		index int
		path  string
	}

	fork, join, cancel := forkjoin.New(
		context.Background(),
		func(ctx context.Context, input openFileInput) (tbls.PrivateKey, error) {
			b, err := os.ReadFile(input.path)
			if err != nil {
				return tbls.PrivateKey{}, errors.Wrap(err, "read file", z.Str("filename", input.path))
			}

			var store Keystore
			if err := json.Unmarshal(b, &store); err != nil {
				return tbls.PrivateKey{}, errors.Wrap(err, "unmarshal keystore", z.Str("filename", input.path))
			}

			password, err := loadPassword(input.path)
			if err != nil {
				return tbls.PrivateKey{}, errors.Wrap(err, "load password", z.Str("filename", input.path))
			}

			secret, err := decrypt(store, password)
			if err != nil {
				return tbls.PrivateKey{}, errors.Wrap(err, "keystore decryption", z.Str("filename", input.path))
			}

			return secret, nil
		},
		forkjoin.WithWorkers(loadStoreWorkers),
	)

	defer cancel()

	resp := make([]tbls.PrivateKey, len(files))

	for idx, f := range files {
		f := f
		idx := idx

		fork(openFileInput{
			index: idx,
			path:  f,
		})
	}

	for result := range join() {
		if result.Err != nil {
			return nil, errors.Wrap(result.Err, "write keys")
		}

		// PSA: this is a concurrent array write, and it works because we're not
		// appending, rather we're accessing individual elements of it in a concurrent way.
		// Concurrent access to a variable must be synchronized if at least one of them involves a write.
		// Spec says:
		//     Structured variables of array, slice, and struct types have elements and fields
		//     that may be addressed individually. Each such element acts like a variable.
		// So each element effectively is a different variable, which is being written only by a single goroutine:
		// no synchronization required.
		resp[result.Input.index] = result.Output
	}

	return resp, nil
}

// LoadKeysSequential returns all secrets stored in dir/keystore-([0-9]*).json EIP-2335 Keystore files
// using password stored in dir/keystore-([0-9]*).txt.
// The keystore files are read sequentially based on their index starting from 0,
// and the returned slice is sorted accordingly.
// Note that the index sequence must be incremental, and the difference between consecutive indices must be exactly
// 1.
func LoadKeysSequential(dir string) ([]tbls.PrivateKey, error) {
	return loadFiles(dir, func(files []string) ([]string, error) {
		newFiles, indices, err := orderByKeystoreNum(files)
		if err != nil {
			return nil, err
		}

		if len(indices) == 0 {
			return nil, errors.New("empty keystore indices")
		}

		if indices[0] != 0 {
			return nil, errors.New("keystore indices must start from zero",
				z.Int("first_index", indices[0]))
		}

		for sliceIdx, idx := range indices {
			if sliceIdx == 0 {
				continue
			}

			lastIdx := indices[sliceIdx-1] + 1

			if lastIdx != idx {
				return nil, errors.New("indices are non sequential",
					z.Int("expected", lastIdx),
					z.Int("got", idx))
			}
		}

		return newFiles, nil
	})
}

// LoadKeys returns all secrets stored in dir/keystore-*.json EIP-2335 Keystore files
// using password stored in dir/keystore-*.txt.
// Keystore files are read in lexicographic order from disk, based on their file name.
func LoadKeys(dir string) ([]tbls.PrivateKey, error) {
	return loadFiles(dir, nil)
}

// orderByKeystoreNum orders keystore file names by their index in ascending order.
func orderByKeystoreNum(files []string) ([]string, []int, error) {
	// Handle one keystore case separately as comparator function is not called while sorting single element slice.
	if len(files) == 1 {
		fileIdx, err := validateKeystoreFilename(files[0])
		if err != nil {
			return nil, nil, err
		}

		return files, []int{fileIdx}, nil
	}

	var sortErr error

	idxSet := make(map[int]struct{})

	sort.Slice(files, func(i, j int) bool {
		firstIdx, err := validateKeystoreFilename(files[i])
		if err != nil {
			sortErr = err

			return false
		}

		secondIdx, err := validateKeystoreFilename(files[j])
		if err != nil {
			sortErr = err

			return false
		}

		idxSet[firstIdx] = struct{}{}
		idxSet[secondIdx] = struct{}{}

		return firstIdx < secondIdx
	})

	if sortErr != nil {
		return nil, nil, sortErr
	}

	var retIdx []int
	for idx := range idxSet {
		retIdx = append(retIdx, idx)
	}

	sort.Ints(retIdx)

	return files, retIdx, nil
}

// Keystore json file representation as a Go struct.
type Keystore struct {
	Crypto      map[string]interface{} `json:"crypto"`
	Description string                 `json:"description"`
	Pubkey      string                 `json:"pubkey"`
	Path        string                 `json:"path"`
	ID          string                 `json:"uuid"`
	Version     uint                   `json:"version"`
}

// Encrypt returns the secret as an encrypted Keystore using pbkdf2 cipher.
func Encrypt(secret tbls.PrivateKey, password string, random io.Reader,
	opts ...keystorev4.Option,
) (Keystore, error) {
	pubKey, err := tbls.SecretToPublicKey(secret)
	if err != nil {
		return Keystore{}, errors.Wrap(err, "marshal pubkey")
	}

	encryptor := keystorev4.New(opts...)
	fields, err := encryptor.Encrypt(secret[:], password)
	if err != nil {
		return Keystore{}, errors.Wrap(err, "encrypt keystore")
	}

	return Keystore{
		Crypto:      fields,
		Description: "", // optional field to help explain the purpose and identify a particular keystore in a user-friendly manner.
		Pubkey:      hex.EncodeToString(pubKey[:]),
		Path:        "m/12381/3600/0/0/0", // https://eips.ethereum.org/EIPS/eip-2334
		ID:          uuid(random),
		Version:     encryptor.Version(),
	}, nil
}

// decrypt returns the secret from the encrypted (empty password) Keystore.
func decrypt(store Keystore, password string) (tbls.PrivateKey, error) {
	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(store.Crypto, password)
	if err != nil {
		return tbls.PrivateKey{}, errors.Wrap(err, "decrypt keystore")
	}

	return tblsconv.PrivkeyFromBytes(secretBytes)
}

// uuid returns a random uuid.
func uuid(random io.Reader) string {
	b := make([]byte, 16)
	_, _ = random.Read(b)

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// loadPassword loads a keystore password from the Keystore's associated password file.
func loadPassword(keyFile string) (string, error) {
	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		return "", errors.New("keystore password file not found " + keyFile)
	}

	passwordFile := strings.Replace(keyFile, ".json", ".txt", 1)
	b, err := os.ReadFile(passwordFile)
	if err != nil {
		return "", errors.Wrap(err, "read password file")
	}

	return string(b), nil
}

// storePassword stores a password to the Keystore's associated password file.
func storePassword(keyFile string, password string) error {
	passwordFile := strings.Replace(keyFile, ".json", ".txt", 1)

	err := os.WriteFile(passwordFile, []byte(password), 0o400)
	if err != nil {
		return errors.Wrap(err, "write password file")
	}

	return nil
}

// randomHex32 returns a random 32 character hex string. It uses crypto/rand.
func randomHex32() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}

// validateKeystoreFilename validates keystore filename and returns index of the keystore file.
func validateKeystoreFilename(file string) (int, error) {
	prefix := filepath.Dir(file)
	extractor := regexp.MustCompile(`keystore-(?:insecure-)?([0-9]+).json`)

	fileName := strings.TrimPrefix(file, prefix)
	if !extractor.MatchString(fileName) {
		return 0, errors.New(
			"keystore filenames do not match expected pattern 'keystore-%d.json' or 'keystore-insecure-%d.json'",
			z.Str("filename", fileName),
		)
	}

	fileIdx, err := strconv.Atoi(extractor.FindStringSubmatch(fileName)[1])
	if err != nil {
		return 0, errors.Wrap(err, "get index from file name")
	}

	return fileIdx, nil
}
