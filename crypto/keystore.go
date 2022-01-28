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
	"github.com/spf13/cobra"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
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

	return k, privKey, pubKey, err
}

// BLSKeyPairToKeystore creates a new EIP-2335 keystore given a BLS12-381 key pair.
// The provided keys should be standalone and not part of hierarchical deterministic derivation.
func BLSKeyPairToKeystore(scalar kyber.Scalar, pubkey kyber.Point, password string) (*Keystore, error) {
	secret, err := scalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	encryptor := keystorev4.New()
	cryptoFields, err := encryptor.Encrypt(secret, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key")
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
	pubShare := DerivePubkey(priPoly.V)
	pubShareHex := BLSPointToHex(pubShare)

	w := (&cobra.Command{}).ErrOrStderr()
	_, _ = fmt.Fprintf(w, "Share #%04d pubkey: %s\n", priPoly.I, pubShareHex)

	pubkey := scheme.PubPoly.Commit()
	pubkeyHex := BLSPointToHex(pubkey)

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
		return nil, nil, fmt.Errorf("failed to decrypt BLS private key: %w", err)
	}

	secret := BLSKeyGroup.Scalar()
	if err := secret.UnmarshalBinary(secretBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal BLS private key: %w", err)
	}
	// Derive public key from private key.
	derivedPubkey := DerivePubkey(secret)
	// Unmarshal public key.
	pubkeyBytes, err := hex.DecodeString(k.Pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal BLS public key: %w", err)
	}

	givenPubkey := BLSKeyGroup.Point()
	if err := givenPubkey.UnmarshalBinary(pubkeyBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to uncompress BLS public key: %w", err)
	}

	if !givenPubkey.Equal(derivedPubkey) {
		return nil, nil, fmt.Errorf("public key mismatch: expected %v, actual %v", givenPubkey, derivedPubkey)
	}

	return secret, derivedPubkey, nil
}

// ReadPlaintextPassword reads a password as the first line from a file.
func ReadPlaintextPassword(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	const maxPasswordLen = 1024

	scn := bufio.NewScanner(io.LimitReader(f, maxPasswordLen))
	if !scn.Scan() {
		return "", io.ErrUnexpectedEOF
	}

	password := scn.Text()
	if len(password) >= maxPasswordLen {
		return "", fmt.Errorf("password very long, aborting")
	}

	return password, nil
}

// WritePlaintextPassword saves a password to a file without leading or trailing whitespace.
//
// If overwrite is set and a file already exists at the given path, the file contents will be erased.
func WritePlaintextPassword(filePath string, overwrite bool, password string) error {
	mode := os.O_WRONLY | os.O_CREATE
	if overwrite {
		mode |= os.O_TRUNC
	} else {
		mode |= os.O_EXCL
	}

	f, err := os.OpenFile(filePath, mode, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, _ = f.WriteString(password)

	return nil
}

// Save marshals and writes the keystore to the given path.
func (k *Keystore) Save(filePath string) error {
	data, err := json.MarshalIndent(k, "", "\t")
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}

	return f.Close()
}

// LoadKeystore reads and unmarshals the keystore from the given path.
func LoadKeystore(filePath string) (*Keystore, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	k := new(Keystore)
	if err := json.Unmarshal(data, k); err != nil {
		return nil, err
	}

	return k, nil
}
