// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package enr provides a minimal implementation of Ethereum Node Records (ENR).
package enr

import (
	"crypto/ecdsa"
	"encoding/base64"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util/rlp"
)

const (
	// keySecp256k1 is the key used to store the secp256k1 public key in the record.
	keySecp256k1 = "secp256k1"

	// keyID is the key used to store the identity scheme in the record, only v4 supported.
	keyID = "id"
	valID = "v4"
)

// Parse parses the given base64 encoded string into a record.
func Parse(enrStr string) (Record, error) {
	if !strings.HasPrefix(enrStr, "enr:") {
		return Record{}, errors.New("missing 'enr:' prefix")
	}

	raw, err := base64.RawURLEncoding.DecodeString(enrStr[4:])
	if err != nil {
		return Record{}, errors.Wrap(err, "invalid base64 encoding")
	}

	elements, err := rlp.DecodeBytesList(raw)
	if err != nil {
		return Record{}, errors.Wrap(err, "invalid rlp encoding")
	}

	if len(elements) < 4 {
		return Record{}, errors.New("invalid enr record, too few elements")
	}
	if len(elements)%2 != 0 {
		return Record{}, errors.New("invalid enr record, odd number of elements")
	}

	r := Record{
		Signature: elements[0],
	}

	for i := 2; i < len(elements); i += 2 {
		switch string(elements[i]) {
		case keySecp256k1:
			r.PubKey, err = crypto.DecompressPubkey(elements[i+1])
			if err != nil {
				return Record{}, errors.Wrap(err, "invalid secp256k1 public key")
			}
		case keyID:
			if string(elements[i+1]) != valID {
				return Record{}, errors.New("non-v4 identity scheme not supported")
			}
		}
	}

	if r.PubKey == nil {
		return Record{}, errors.New("missing secp256k1 public key")
	}

	if err := verify(r.PubKey, r.Signature, rlp.EncodeBytesList(elements[1:])); err != nil {
		return Record{}, err
	}

	return r, nil
}

// New returns a new enr record for the given private key.
func New(privkey *ecdsa.PrivateKey) (Record, error) {
	sig, err := sign(privkey)
	if err != nil {
		return Record{}, err
	}

	return Record{
		PubKey:    &privkey.PublicKey,
		Signature: sig,
	}, nil
}

// Record represents an Ethereum Node Record.
type Record struct {
	// Node public key (identity).
	PubKey *ecdsa.PublicKey
	// Signature of the record.
	Signature []byte
}

// String returns the base64 encoded string representation of the record.
func (r Record) String() string {
	return "enr:" + base64.RawURLEncoding.EncodeToString(encodeElements(r.Signature, r.PubKey))
}

// encodeElements return the RLP encoding of a minimal set of record elements including optional signature.
func encodeElements(signature []byte, pubkey *ecdsa.PublicKey) []byte {
	elements := [][]byte{
		{}, // Sequence number=0
		[]byte(keySecp256k1), crypto.CompressPubkey(pubkey),
		[]byte(keyID), []byte(valID),
	}

	if len(signature) > 0 {
		elements = append([][]byte{signature}, elements...)
	}

	return rlp.EncodeBytesList(elements)
}

// sign returns a enr record signature.
func sign(privkey *ecdsa.PrivateKey) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(encodeElements(nil, &privkey.PublicKey))
	digest := h.Sum(nil)

	sig, err := crypto.Sign(digest, privkey)
	if err != nil {
		return nil, errors.Wrap(err, "sign enr")
	}

	return sig[:len(sig)-1], nil // remove v (recovery id), nil
}

// verify return an error if the record signature verification fails.
func verify(pubkey *ecdsa.PublicKey, signature, rawExclSig []byte) error {
	h := sha3.NewLegacyKeccak256()
	h.Write(rawExclSig)
	digest := h.Sum(nil)

	if !crypto.VerifySignature(crypto.CompressPubkey(pubkey), digest, signature) {
		return errors.New("invalid enr Signature")
	}

	return nil
}
