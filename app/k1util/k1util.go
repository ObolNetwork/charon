// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package k1util provides helper function for working with secp256k1 keys.
package k1util

import (
	"encoding/hex"
	"os"
	"strings"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/libp2p/go-libp2p/core/crypto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	scalarLen = 32
	// k1HashLen is the length of secp256k1 signature hash/digest.
	k1HashLen = 32
	// k1SigLen is the Ethereum format length of secp256k1 signatures.
	k1SigLen = 65
	// k1RecIdx is the Ethereum format secp256k1 signature recovery id index.
	k1RecIdx = 64

	// compactSigMagicOffset is a value used when creating the compact signature
	// recovery code inherited from Bitcoin.
	compactSigMagicOffset = 27
)

// PublicKeyFromLibP2P returns the libp2p public key as a secp256k1 public key.
func PublicKeyFromLibP2P(key crypto.PubKey) (*k1.PublicKey, error) {
	k1Key, ok := key.(*crypto.Secp256k1PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type")
	}

	return (*k1.PublicKey)(k1Key), nil
}

// Sign returns a signature from input data.
//
// The produced signature is 65 bytes in the [R || S || V] format where V is 0 or 1.
func Sign(key *k1.PrivateKey, hash []byte) ([]byte, error) {
	if len(hash) != k1HashLen {
		return nil, errors.New("signing hash/digest not 32 bytes", z.Int("len", len(hash)))
	}

	sig := ecdsa.SignCompact(key, hash, false)

	// Convert signature from "compact" into "Ethereum R S V" format.

	recovery := sig[0] // Compact sig recovery code is the value 27 + public key recovery code
	sig = append(sig[1:], recovery-compactSigMagicOffset)

	return sig, nil
}

// Verify65 returns whether the 65 byte signature is valid for the provided hash
// and secp256k1 public key.
//
// Note the signature MUST be 64 bytes in the [R || S || V] format where V is the recovery ID.
func Verify65(pubkey *k1.PublicKey, hash []byte, sig []byte) (bool, error) {
	recovered, err := Recover(hash, sig)
	if err != nil {
		return false, err
	}

	return pubkey.IsEqual(recovered), nil
}

// Verify64 returns whether the 64 byte signature is valid for the provided hash
// and secp256k1 public key.
//
// Note the signature MUST be 64 bytes in the [R || S] format without recovery ID.
func Verify64(pubkey *k1.PublicKey, hash []byte, sig []byte) (bool, error) {
	if len(sig) != 2*scalarLen {
		return false, errors.New("signature not 64 bytes")
	}

	r, err := to32Scalar(sig[:scalarLen])
	if err != nil {
		return false, errors.Wrap(err, "invalid signature R")
	}

	s, err := to32Scalar(sig[scalarLen : 2*scalarLen])
	if err != nil {
		return false, errors.Wrap(err, "invalid signature S")
	}

	return ecdsa.NewSignature(r, s).Verify(hash, pubkey), nil
}

// Recover returns the recovered public key from signature hash.
//
// Note the signature MUST be 65 bytes in the [R || S || V] format where V is 0/27 or 1/28.
func Recover(hash []byte, sig []byte) (*k1.PublicKey, error) {
	if len(hash) != k1HashLen {
		return nil, errors.New("signing hash/digest not 32 bytes", z.Int("len", len(hash)))
	}

	if len(sig) != k1SigLen {
		return nil, errors.New("signature not 65 bytes")
	}

	// Convert from ethereum RSV format
	if sig[k1RecIdx] != 0 && sig[k1RecIdx] != 1 && sig[k1RecIdx] != compactSigMagicOffset && sig[k1RecIdx] != compactSigMagicOffset+1 {
		return nil, errors.New("invalid recovery id", z.Any("id", sig[k1RecIdx]))
	}

	// Put recovery ID first.
	sig = append([]byte{sig[k1RecIdx]}, sig[:k1RecIdx]...)

	if sig[0] == 0 || sig[0] == 1 {
		sig[0] += compactSigMagicOffset // Make the recovery ID 27 or 28 since that is required below.
	}

	pubkey, _, err := ecdsa.RecoverCompact(sig, hash)
	if err != nil {
		return nil, errors.Wrap(err, "parse signature")
	}

	return pubkey, nil
}

// Load returns a private key by reading it from a hex encoded file on disk.
func Load(file string) (*k1.PrivateKey, error) {
	hexStr, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "read private key from disk", z.Str("file", file))
	}

	b, err := hex.DecodeString(strings.TrimSpace(string(hexStr)))
	if err != nil {
		return nil, errors.Wrap(err, "decode private key hex")
	}

	return k1.PrivKeyFromBytes(b), nil
}

// Save writes the hex encoded private key to disk.
func Save(key *k1.PrivateKey, file string) error {
	hexStr := hex.EncodeToString(key.Serialize())

	if err := os.WriteFile(file, []byte(hexStr), 0o600); err != nil {
		return errors.Wrap(err, "write private key to disk", z.Str("file", file))
	}

	return nil
}

// to32Scalar returns the 256-bit big-endian unsigned
// integer as a scalar.
func to32Scalar(b []byte) (*k1.ModNScalar, error) {
	if len(b) != scalarLen {
		return nil, errors.New("invalid scalar length")
	}

	// Strip leading zeroes from S.
	for len(b) > 0 && b[0] == 0x00 {
		b = b[1:]
	}

	var s k1.ModNScalar
	if overflow := s.SetByteSlice(b); overflow {
		return nil, errors.New("scalar overflow")
	} else if s.IsZero() {
		return nil, errors.New("zero overflow")
	}

	return &s, nil
}
