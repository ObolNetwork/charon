// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/crypto"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// insecureCost decreases the cipher key cost from the default 18 to 4 which speeds up
	// encryption and decryption at the cost of security.
	insecureCost = 4

	// loadStoreWorkers is the amount of workers to use when loading/storing keys concurrently.
	loadStoreWorkers = 10
)

// IndexedKeyShare represents a share in the context of a Charon cluster,
// alongside its index.
type IndexedKeyShare struct {
	Share tbls.PrivateKey
	Index int
}

// ValidatorShares maps each ValidatorPubkey to the associated KeyShare.
type ValidatorShares map[core.PubKey]IndexedKeyShare

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
//
// Note it doesn't ensure the folder dir exists.
func StoreKeys(secrets []tbls.PrivateKey, dir string) error {
	return storeKeysInternal(secrets, dir, "keystore-%d.json")
}

func storeKeysInternal(secrets []tbls.PrivateKey, dir string, filenameFmt string, opts ...keystorev4.Option) error {
	if err := checkDir(dir); err != nil {
		return err
	}

	type data struct {
		index  int
		secret tbls.PrivateKey
	}

	fork, join, cancel := forkjoin.New(
		context.Background(),
		func(_ context.Context, d data) (any, error) {
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

			return nil, nil //nolint:nilnil
		},
		forkjoin.WithWorkers(loadStoreWorkers),
	)

	defer cancel()

	for i, secret := range secrets {
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

// Keystore json file representation as a Go struct.
type Keystore struct {
	Crypto      map[string]any `json:"crypto"`
	Description string         `json:"description"`
	Pubkey      string         `json:"pubkey"`
	Path        string         `json:"path"`
	ID          string         `json:"uuid"`
	Version     uint           `json:"version"`
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

// checkDir checks if dir exists and is a directory.
func checkDir(dir string) error {
	if info, err := os.Stat(dir); os.IsNotExist(err) {
		return errors.Wrap(err, "keystore dir does not exist", z.Str("dir", dir))
	} else if err != nil {
		return errors.Wrap(err, "check keystore dir", z.Str("dir", dir))
	} else if !info.IsDir() {
		return errors.New("keystore dir is not a directory", z.Str("dir", dir))
	}

	return nil
}

// KeysharesToValidatorPubkey maps each share in cl to the associated validator private key.
// It returns an error if a keyshare does not appear in cl, or if there's a validator public key associated to no
// keyshare.
func KeysharesToValidatorPubkey(cl *manifestpb.Cluster, shares []tbls.PrivateKey) (ValidatorShares, error) {
	ret := make(map[core.PubKey]IndexedKeyShare)

	var pubShares []tbls.PublicKey

	for _, share := range shares {
		ps, err := tbls.SecretToPublicKey(share)
		if err != nil {
			return nil, errors.Wrap(err, "private share to public share")
		}

		pubShares = append(pubShares, ps)
	}

	// this is sadly a O(n^2) search
	for _, validator := range cl.Validators {
		valHex := fmt.Sprintf("0x%x", validator.PublicKey)

		valPubShares := make(map[tbls.PublicKey]struct{})
		for _, valShare := range validator.PubShares {
			valPubShares[tbls.PublicKey(valShare)] = struct{}{}
		}

		found := false
		for shareIdx, share := range pubShares {
			if _, ok := valPubShares[share]; !ok {
				continue
			}

			ret[core.PubKey(valHex)] = IndexedKeyShare{
				Share: shares[shareIdx],
				Index: shareIdx + 1,
			}
			found = true

			break
		}

		if !found {
			return nil, errors.New("public key share from provided private key share not found in provided lock")
		}
	}

	if len(ret) != len(cl.Validators) {
		return nil, errors.New("amount of key shares don't match amount of validator public keys")
	}

	return ret, nil
}

// ShareIdxForCluster returns the share index for the Charon cluster's ENR identity key, given a *manifestpb.Cluster.
func ShareIdxForCluster(cl *manifestpb.Cluster, identityKey k1.PublicKey) (uint64, error) {
	pids, err := manifest.ClusterPeerIDs(cl)
	if err != nil {
		return 0, errors.Wrap(err, "cluster peer ids")
	}

	k := crypto.Secp256k1PublicKey(identityKey)

	shareIdx := -1
	for _, pid := range pids {
		if !pid.MatchesPublicKey(&k) {
			continue
		}

		nIdx, err := manifest.ClusterNodeIdx(cl, pid)
		if err != nil {
			return 0, errors.Wrap(err, "cluster node idx")
		}

		shareIdx = nIdx.ShareIdx
	}

	if shareIdx == -1 {
		return 0, errors.New("node index for loaded enr not found in cluster lock")
	}

	return uint64(shareIdx), nil
}
