// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/bls"
	"github.com/google/uuid"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
)

// Keystore describes the EIP-2335 BLS12-381 keystore file format.
//
// https://eips.ethereum.org/EIPS/eip-2335
type Keystore struct {
	Crypto      map[string]interface{} `json:"crypto"`      // checksum, cipher, kdf
	Description string                 `json:"description"` // free-form text string explaining keystore purpose
	UUID        string                 `json:"uuid"`        // random UUID
	Pubkey      string                 `json:"pubkey"`      // BLS12-381 hex public key
	Path        string                 `json:"path"`        // EIP-2334 derivation path if hierarchical deriv, otherwise empty
	Version     uint                   `json:"version"`     // must be 4
}

// NewBLSKeystore creates a new keystore with a random BLS12-381 private key.
func NewBLSKeystore(password string) (*Keystore, kyber.Scalar, kyber.Point, error) {
	privKey, pubKey := bls.NewSchemeOnG1(BLSPairing).NewKeyPair(BLSPairing.RandomStream())

	k, err := BLSKeyPairToKeystore(privKey, pubKey, password)
	if err != nil {
		return nil, nil, nil, err
	}

	return k, privKey, pubKey, nil
}

// BLSKeyPairToKeystore creates a new EIP-2335 keystore given a BLS12-381 key pair.
// The provided keys should be standalone and not part of hierarchical deterministic derivation.
func BLSKeyPairToKeystore(scalar kyber.Scalar, pubkey kyber.Point, password string) (*Keystore, error) {
	secret, err := scalar.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal private key")
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "new uuid")
	}

	encryptor := keystorev4.New()
	cryptoFields, err := encryptor.Encrypt(secret, password)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt key")
	}

	return &Keystore{
		Crypto:  cryptoFields,
		UUID:    id.String(),
		Pubkey:  BLSPointToHex(pubkey),
		Path:    "", // path is empty since we don't use derivation
		Version: encryptor.Version(),
	}, nil
}

// TBLSShareToKeystore constructs a new keystore from a threshold BLS private key share.
//
// Prints the public key as a side effect.
func TBLSShareToKeystore(scheme *TBLSScheme, priPoly *share.PriShare, password string) (*Keystore, error) {
	pubkey := scheme.PubPoly.Commit()
	pubkeyHex := BLSPointToHex(pubkey)
	pubShare := DerivePubkey(priPoly.V)

	keyStore, err := BLSKeyPairToKeystore(priPoly.V, pubShare, password)
	if err != nil {
		return nil, err
	}

	keyStore.Description = fmt.Sprintf("Obol Eth2 validator %s i=%d t=%d",
		pubkeyHex, priPoly.I, scheme.Threshold())

	return keyStore, nil
}

// BLSKeyPair returns the BLS12-381 keypair stored in a keystore.
func (k *Keystore) BLSKeyPair(password string) (kyber.Scalar, kyber.Point, error) {
	// Decrypt private key.
	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(k.Crypto, password)
	if err != nil {
		return nil, nil, errors.Wrap(err, "decrypt BLS private key")
	}

	secret := BLSKeyGroup.Scalar()
	if err := secret.UnmarshalBinary(secretBytes); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal BLS private key")
	}
	// Derive public key from private key.
	derivedPubkey := DerivePubkey(secret)
	// Unmarshal public key.
	pubkeyBytes, err := hex.DecodeString(k.Pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "decode BLS public key")
	}

	givenPubkey := BLSKeyGroup.Point()
	if err := givenPubkey.UnmarshalBinary(pubkeyBytes); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal BLS public key")
	}

	if !givenPubkey.Equal(derivedPubkey) {
		return nil, nil, errors.New("mismatching public keys")
	}

	return secret, derivedPubkey, nil
}

// ReadPlaintextPassword reads a password as the first line from a file.
func ReadPlaintextPassword(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", errors.Wrap(err, "open file")
	}
	defer f.Close()

	const maxPasswordLen = 1024

	scn := bufio.NewScanner(io.LimitReader(f, maxPasswordLen))
	if !scn.Scan() {
		return "", errors.New("scanning password file")
	}

	password := scn.Text()
	if len(password) >= maxPasswordLen {
		return "", errors.New("password too long")
	}

	return password, nil
}

// WritePlaintextPassword saves a password to a file without leading or trailing whitespace.
//
// If overwrite is set and a file already exists at the given path, the file contents will be erased.
func WritePlaintextPassword(filePath string, password string) error {
	mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL

	f, err := os.OpenFile(filePath, mode, 0o600)
	if err != nil {
		return errors.Wrap(err, "open file")
	}
	defer f.Close()

	_, _ = f.WriteString(password)

	return nil
}

// Save marshals and writes the keystore to the given path.
func (k *Keystore) Save(filePath string) error {
	data, err := json.MarshalIndent(k, "", "\t")
	if err != nil {
		return errors.Wrap(err, "marshal keystore")
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Wrap(err, "open file")
	}

	if _, err := f.Write(data); err != nil {
		return errors.Wrap(err, "write file")
	}

	if err := f.Close(); err != nil {
		return errors.Wrap(err, "close file")
	}

	return nil
}

// LoadKeystore reads and unmarshals the keystore from the given path.
func LoadKeystore(filePath string) (*Keystore, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "read keystore")
	}

	k := new(Keystore)
	if err := json.Unmarshal(data, k); err != nil {
		return nil, errors.Wrap(err, "unmarshal keystore")
	}

	return k, nil
}
