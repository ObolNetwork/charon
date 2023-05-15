// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tbls

import (
	"io"
	"sync"
	"testing"
)

var (
	impl     Implementation = Herumi{}
	implLock sync.Mutex
)

type (
	// PublicKey is a byte slice containing a compressed BLS12-381 public key.
	PublicKey [48]byte

	// PrivateKey is a byte slice containing a compressed BLS12-381 private key.
	PrivateKey [32]byte

	// Signature is a byte slice containing a BLS12-381 signature.
	Signature [96]byte
)

// Implementation defines the backing implementation for all the public functions of this package.
type Implementation interface {
	// GenerateSecretKey generates a secret key and returns its compressed serialized representation.
	GenerateSecretKey() (PrivateKey, error)

	// GenerateInsecureKey generates a insecure deterministic secret key using the provided random number generator
	// and returns its compressed serialized representation.
	GenerateInsecureKey(t *testing.T, random io.Reader) (PrivateKey, error)

	// SecretToPublicKey extracts the public key associated with the secret passed in input, and returns its
	// compressed serialized representation.
	SecretToPublicKey(PrivateKey) (PublicKey, error)

	// ThresholdSplit splits a compressed secret into total units of secret keys, with the given threshold.
	// It returns a map that associates each private, compressed private key to its ID.
	ThresholdSplit(secret PrivateKey, total uint, threshold uint) (map[int]PrivateKey, error)

	// RecoverSecret recovers the original secret off the input shares.
	RecoverSecret(shares map[int]PrivateKey, total uint, threshold uint) (PrivateKey, error)

	// ThresholdAggregate aggregates the partial signatures passed in input in the final original signature.
	ThresholdAggregate(partialSignaturesByIndex map[int]Signature) (Signature, error)

	// Verify verifies that signature has been produced with the private key associated with compressedPublicKey, on
	// the provided data.
	Verify(compressedPublicKey PublicKey, data []byte, signature Signature) error

	// Sign signs data with the provided private key, and returns the resulting signature.
	// This function works on both shares of private keys, and complete private keys.
	Sign(privateKey PrivateKey, data []byte) (Signature, error)

	// VerifyAggregate is the BLS standard FastAggregateVerify call, as defined by the standard:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-3.3.4.
	VerifyAggregate(shares []PublicKey, signature Signature, data []byte) error

	// Aggregate combines signs in a single Signature with standard BLS signature aggregation,
	// as defined by the standard: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-2.8.
	Aggregate(signs []Signature) (Signature, error)
}

// SetImplementation sets newImpl as the package backing implementation.
func SetImplementation(newImpl Implementation) {
	implLock.Lock()
	defer implLock.Unlock()
	impl = newImpl
}

// GenerateSecretKey generates a secret key and returns its compressed serialized representation.
func GenerateSecretKey() (PrivateKey, error) {
	return impl.GenerateSecretKey()
}

// GenerateInsecureKey generates a insecure deterministic secret key using the provided random number generator
// and returns its compressed serialized representation.
func GenerateInsecureKey(t *testing.T, random io.Reader) (PrivateKey, error) {
	t.Helper()
	return impl.GenerateInsecureKey(t, random)
}

// SecretToPublicKey extracts the public key associated with the secret passed in input, and returns its
// compressed serialized representation.
func SecretToPublicKey(secret PrivateKey) (PublicKey, error) {
	return impl.SecretToPublicKey(secret)
}

// ThresholdSplit splits a compressed secret into total units of secret keys, with the given threshold.
// It returns a map that associates each private, compressed private key to its ID.
func ThresholdSplit(secret PrivateKey, total uint, threshold uint) (map[int]PrivateKey, error) {
	return impl.ThresholdSplit(secret, total, threshold)
}

// RecoverSecret recovers the original secret off the input shares.
func RecoverSecret(shares map[int]PrivateKey, total uint, threshold uint) (PrivateKey, error) {
	return impl.RecoverSecret(shares, total, threshold)
}

// ThresholdAggregate aggregates the partial signatures passed in input in the final original signature.
func ThresholdAggregate(partialSignaturesByIndex map[int]Signature) (Signature, error) {
	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

// Verify verifies that signature has been produced with the private key associated with compressedPublicKey, on
// the provided data.
func Verify(compressedPublicKey PublicKey, data []byte, signature Signature) error {
	return impl.Verify(compressedPublicKey, data, signature)
}

// Sign signs data with the provided private key, and returns the resulting signature.
// This function works on both shares of private keys, and complete private keys.
func Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	return impl.Sign(privateKey, data)
}

// VerifyAggregate is the BLS standard FastAggregateVerify call, as defined by the standard:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-3.3.4.
func VerifyAggregate(shares []PublicKey, signature Signature, data []byte) error {
	return impl.VerifyAggregate(shares, signature, data)
}

// Aggregate combines signs in a single Signature with standard BLS signature aggregation,
// as defined by the standard: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-2.8.
func Aggregate(signs []Signature) (Signature, error) {
	return impl.Aggregate(signs)
}
