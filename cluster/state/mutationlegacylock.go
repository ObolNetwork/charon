// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"
	"reflect"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
)

func NewClusterFromLock(lock cluster.Lock) (Cluster, error) {
	signed, err := NewLegacyLock(lock)
	if err != nil {
		return Cluster{}, err
	}

	return Materialise(&pbv1.SignedMutationList{Mutations: []*pbv1.SignedMutation{signed}})
}

// NewLegacyLock return a new legacy lock mutation from the provided lock.
func NewLegacyLock(lock cluster.Lock) (*pbv1.SignedMutation, error) {
	timestamp, err := time.Parse(time.RFC3339, lock.Timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "parse lock timestamp")
	}

	b, err := json.Marshal(lock)
	if err != nil {
		return nil, errors.Wrap(err, "marshal lock")
	}

	lockAny, err := anypb.New(&pbv1.LegacyLock{Json: b})
	if err != nil {
		return nil, errors.Wrap(err, "lock to any")
	}

	var zeroParent [32]byte

	return &pbv1.SignedMutation{
		Mutation: &pbv1.Mutation{
			Parent:    zeroParent[:], // Empty parent
			Type:      string(TypeLegacyLock),
			Timestamp: timestamppb.New(timestamp),
			Data:      lockAny,
		},
		// No signer or signature
	}, nil
}

// verifyLegacyLock verifies that the signed mutation is a valid legacy lock.
func verifyLegacyLock(signed *pbv1.SignedMutation) error {
	if MutationType(signed.Mutation.Type) != TypeLegacyLock {
		return errors.New("invalid mutation type")
	}

	if err := verifyEmptySig(signed); err != nil {
		return errors.Wrap(err, "verify empty signature")
	}

	legacyLock := new(pbv1.LegacyLock)
	if err := signed.Mutation.Data.UnmarshalTo(legacyLock); err != nil {
		return errors.New("mutation data to legacy lock")
	}

	var lock cluster.Lock
	if err := json.Unmarshal(legacyLock.Json, &lock); err != nil {
		return errors.Wrap(err, "unmarshal lock")
	}
	// return lock.VerifySignatures()

	return nil
}

// transformLegacyLock transforms the cluster state with the provided legacy lock mutation.
func transformLegacyLock(input Cluster, signed *pbv1.SignedMutation) (Cluster, error) {
	if !reflect.ValueOf(input).IsZero() {
		// TODO(corver): Find a better way to verify input cluster is zero.
		return Cluster{}, errors.New("legacy lock not first mutation")
	}

	if err := verifyLegacyLock(signed); err != nil {
		return Cluster{}, errors.Wrap(err, "verify legacy lock")
	}

	legacyLock := new(pbv1.LegacyLock)
	if err := signed.Mutation.Data.UnmarshalTo(legacyLock); err != nil {
		return Cluster{}, errors.New("mutation data to legacy lock")
	}

	var lock cluster.Lock
	if err := json.Unmarshal(legacyLock.Json, &lock); err != nil {
		return Cluster{}, errors.Wrap(err, "unmarshal lock")
	}

	var ops []*pbv1.Operator
	for _, operator := range lock.Operators {
		ops = append(ops, &pbv1.Operator{
			Address: operator.Address,
			Enr:     operator.ENR,
		})
	}

	if len(lock.ValidatorAddresses) != len(lock.Validators) {
		return Cluster{}, errors.New("validator addresses and validators length mismatch")
	}

	var vals []*pbv1.Validator
	for i, validator := range lock.Validators {
		val, err := ValidatorToProto(validator, lock.ValidatorAddresses[i])
		if err != nil {
			return Cluster{}, errors.Wrap(err, "validator to proto")
		}

		vals = append(vals, val)
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
