// Copyright © 2023 Obol Labs Inc.

package tbls

import (
	"encoding"
	"fmt"
)

/*
`tbls` package operations:
- key generation
- threshold cryptography
 - key splitting
 - key aggregation (public, private)
 - signature verification and aggregation
 - simple signature aggregation
 - simple signature verification
 - signature on a byte slice
 - signature with a partial key
*/

type ThresholdManager struct {
	total     uint
	threshold uint
	generator ThresholdGenerator
}

func NewThresholdManager(generator ThresholdGenerator, total, threshold uint) (ThresholdManager, error) {
	if generator == nil {
		return ThresholdManager{}, fmt.Errorf("generator can't be nil")
	}

	if threshold > total {
		return ThresholdManager{}, fmt.Errorf("threshold can't be greater than total")
	}

	if threshold == 0 {
		return ThresholdManager{}, fmt.Errorf("threshold can't be zero")
	}

	if total == 0 {
		return ThresholdManager{}, fmt.Errorf("total can't be zero")
	}

	return ThresholdManager{
		threshold: threshold,
		total:     total,
		generator: generator,
	}, nil
}

func (tm ThresholdManager) Generate() ([]PartialPrivateKey, error) {
	pk, err := tm.generator.Generate()
	if err != nil {
		return nil, err
	}

	return tm.generator.Split(pk, tm.total, tm.threshold)
}

// VerifyAggregate verifies all partial signatures against a message and aggregates them.
// It returns the aggregated signature and slice of valid partial signature identifiers.
func (tm ThresholdManager) VerifyAggregate(pubkeys []PartialPublicKey, partialSigs []PartialSignature, msg []byte) (Signature, []uint, error) {
	if len(partialSigs) < int(tm.threshold) {
		return nil, nil, fmt.Errorf("insufficient signatures")
	}

	var (
		signers   []uint
		validSigs []PartialSignature
	)

	for idx := 0; idx < len(partialSigs); idx++ {
		signature := partialSigs[idx]
		pubkey := pubkeys[idx]

		if err := signature.Verify(pubkey, msg); err != nil {
			continue
		}

		validSigs = append(validSigs, signature)
		signers = append(signers, pubkey.ID())
	}

	if len(validSigs) < int(tm.threshold) {
		return nil, nil, fmt.Errorf("insufficient valid signatures")
	}

	aggSig, err := tm.generator.CombineSignatures(partialSigs, pubkeys)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot aggregate signatures after verification, %w", err)
	}

	return aggSig, signers, nil
}

// Aggregate aggregates partialSigs into a single Signature, with ID's taken from pubkeys.
func (tm ThresholdManager) Aggregate(pubkeys []PartialPublicKey, partialSigs []PartialSignature) (Signature, error) {
	aggSig, err := tm.generator.CombineSignatures(partialSigs, pubkeys)
	if err != nil {
		return nil, fmt.Errorf("cannot aggregate signatures after verification, %w", err)
	}

	return aggSig, nil
}

// ThresholdGenerator generates threshold public and private keys according to
// the specified parameters.
type ThresholdGenerator interface {
	// Split splits original into total amount of PartialPrivateKey's, with threshold
	// amount of them needed to recover secret.
	Split(original PrivateKey, total, threshold uint) ([]PartialPrivateKey, error)

	// RecoverPrivateKey recombines the PartialPrivateKey's back to the original PrivateKey.
	RecoverPrivateKey([]PartialPrivateKey) (PrivateKey, error)

	// CombineSignatures combines all the input PartialSignature's in a complete
	// Signature.
	CombineSignatures([]PartialSignature, []PartialPublicKey) (Signature, error)

	// Generate generates a new PrivateKey from the OS source of entropy
	Generate() (PrivateKey, error)
}

// PublicKey is a BLS12-381 public key.
// It represents a full public key, not a share of it.
type PublicKey interface {
	encoding.TextMarshaler
}

// PrivateKey is a BLS12-381 private key.
// It represents a full private key, not a share of it.
type PrivateKey interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	PublicKey() PublicKey
	Sign(data []byte) (Signature, error)
}

// PartialPublicKey is a share of a full BLS12-381 key.
type PartialPublicKey interface {
	PublicKey
	ID() uint
}

// PartialPrivateKey is a share of a full BLS12-381 key.
type PartialPrivateKey interface {
	PrivateKey
	ID() uint
}

// Signature represents a BLS12-381 signature made with a PrivateKey.
type Signature interface {
	Verify(pk PublicKey, message []byte) error
}

// PartialSignature represents a BLS12-381 signature made with a PartialPrivateKey.
type PartialSignature interface {
	Verify(pk PartialPublicKey, message []byte) error
}
