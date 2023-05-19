// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"reflect"
	"time"

	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

func NewClusterFromLock(lock cluster.Lock) (Cluster, error) {
	signed, err := NewLegacyLock(lock)
	if err != nil {
		return Cluster{}, err
	}

	return Materialise(RawDAG{signed})
}

// NewLegacyLock return a new legacy lock mutation from the provided lock.
func NewLegacyLock(lock cluster.Lock) (SignedMutation, error) {
	timestamp, err := time.Parse(time.RFC3339, lock.Timestamp)
	if err != nil {
		return SignedMutation{}, errors.Wrap(err, "parse lock timestamp")
	}

	return SignedMutation{
		Mutation: Mutation{
			Parent:    [32]byte{}, // Empty parent
			Type:      TypeLegacyLock,
			Timestamp: timestamp,
			Data:      lockWrapper{lock},
		},
		// No signer or signature
	}, nil
}

// lockWrapper wraps the lock hash using the lockhash directly as the mutation data hash.
type lockWrapper struct {
	cluster.Lock
}

// HashTreeRootWith writes the lock hash to the hasher.
func (l lockWrapper) HashTreeRootWith(hw ssz.HashWalker) error {
	indx := hw.Index()

	if err := putBytesN(hw, l.Lock.LockHash, 32); err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// verifyLegacyLock verifies that the signed mutation is a valid legacy lock.
func verifyLegacyLock(signed SignedMutation) error {
	if signed.Mutation.Type != TypeLegacyLock {
		return errors.New("invalid mutation type")
	}

	if _, ok := signed.Mutation.Data.(lockWrapper); !ok {
		return errors.New("invalid mutation data")
	}

	if err := verifyEmptySig(signed); err != nil {
		return errors.Wrap(err, "verify empty signature")
	}

	// TODO(corevr): Figure out how no-verify works here
	// wrapper, ok := signed.Mutation.Data.(lockWrapper)
	// if !ok {
	// 	return errors.New("data not a lock")
	// }
	//
	// return wrapper.Lock.VerifySignatures()

	return nil
}

// transformLegacyLock transforms the cluster state with the provided legacy lock mutation.
func transformLegacyLock(input Cluster, signed SignedMutation) (Cluster, error) {
	if !reflect.ValueOf(input).IsZero() {
		// TODO(corver): Find a better way to verify input cluster is zero.
		return Cluster{}, errors.New("legacy lock not first mutation")
	}

	if err := verifyLegacyLock(signed); err != nil {
		return Cluster{}, errors.Wrap(err, "verify legacy lock")
	}

	lock := signed.Mutation.Data.(lockWrapper) // Can just cast, already verified data is a lock

	var ops []Operator
	for _, operator := range lock.Operators {
		ops = append(ops, Operator{
			Address: operator.Address,
			ENR:     operator.ENR,
		})
	}

	if len(lock.ValidatorAddresses) != len(lock.Validators) {
		return Cluster{}, errors.New("validator addresses and validators length mismatch")
	}

	var vals []Validator
	for i, validator := range lock.Validators {
		vals = append(vals, Validator{
			PubKey:              validator.PubKey,
			PubShares:           validator.PubShares,
			FeeRecipientAddress: lock.ValidatorAddresses[i].FeeRecipientAddress,
			WithdrawalAddress:   lock.ValidatorAddresses[i].WithdrawalAddress,
			BuilderRegistration: registrationsFromLock(validator.BuilderRegistration),
		})
	}

	return Cluster{
		Name:         lock.Name,
		Threshold:    lock.Threshold,
		DKGAlgorithm: lock.DKGAlgorithm,
		ForkVersion:  lock.ForkVersion,
		Validators:   vals,
		Operators:    ops,
	}, nil
}

func registrationsFromLock(r cluster.BuilderRegistration) BuilderRegistration {
	return BuilderRegistration{
		Message: Registration{
			FeeRecipient: r.Message.FeeRecipient,
			GasLimit:     r.Message.GasLimit,
			Timestamp:    r.Message.Timestamp,
			PubKey:       r.Message.PubKey,
		},
		Signature: r.Signature,
	}
}
