// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"encoding/json"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

func NewClusterFromLock(lock cluster.Lock) (*manifestpb.Cluster, error) {
	signed, err := NewLegacyLock(lock)
	if err != nil {
		return nil, err
	}

	return Materialise(&manifestpb.SignedMutationList{Mutations: []*manifestpb.SignedMutation{signed}})
}

// NewLegacyLock return a new legacy lock mutation from the provided lock.
func NewLegacyLock(lock cluster.Lock) (*manifestpb.SignedMutation, error) {
	timestamp, err := time.Parse(time.RFC3339, lock.Timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "parse lock timestamp")
	}

	b, err := json.Marshal(lock)
	if err != nil {
		return nil, errors.Wrap(err, "marshal lock")
	}

	lockAny, err := anypb.New(&manifestpb.LegacyLock{Json: b})
	if err != nil {
		return nil, errors.Wrap(err, "lock to any")
	}

	var zeroParent [32]byte

	return &manifestpb.SignedMutation{
		Mutation: &manifestpb.Mutation{
			Parent:    zeroParent[:], // Empty parent
			Type:      string(TypeLegacyLock),
			Timestamp: timestamppb.New(timestamp),
			Data:      lockAny,
		},
		// No signer or signature
	}, nil
}

// verifyLegacyLock verifies that the signed mutation is a valid legacy lock.
func verifyLegacyLock(signed *manifestpb.SignedMutation) error {
	if MutationType(signed.Mutation.Type) != TypeLegacyLock {
		return errors.New("invalid mutation type")
	}

	if err := verifyEmptySig(signed); err != nil {
		return errors.Wrap(err, "verify empty signature")
	}

	legacyLock := new(manifestpb.LegacyLock)
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

// transformLegacyLock transforms the cluster manifest with the provided legacy lock mutation.
func transformLegacyLock(input *manifestpb.Cluster, signed *manifestpb.SignedMutation) (*manifestpb.Cluster, error) {
	if !isZeroProto(input) {
		return nil, errors.New("legacy lock not first mutation")
	}

	if err := verifyLegacyLock(signed); err != nil {
		return nil, errors.Wrap(err, "verify legacy lock")
	}

	legacyLock := new(manifestpb.LegacyLock)
	if err := signed.Mutation.Data.UnmarshalTo(legacyLock); err != nil {
		return nil, errors.New("mutation data to legacy lock")
	}

	var lock cluster.Lock
	if err := json.Unmarshal(legacyLock.Json, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal lock")
	}

	var ops []*manifestpb.Operator
	for _, operator := range lock.Operators {
		ops = append(ops, &manifestpb.Operator{
			Address: operator.Address,
			Enr:     operator.ENR,
		})
	}

	if len(lock.ValidatorAddresses) != len(lock.Validators) {
		return nil, errors.New("validator addresses and validators length mismatch")
	}

	var vals []*manifestpb.Validator
	for i, validator := range lock.Validators {
		val, err := ValidatorToProto(validator, lock.ValidatorAddresses[i])
		if err != nil {
			return nil, errors.Wrap(err, "validator to proto")
		}

		vals = append(vals, val)
	}

	return &manifestpb.Cluster{
		Name:         lock.Name,
		Threshold:    int32(lock.Threshold),
		DkgAlgorithm: lock.DKGAlgorithm,
		ForkVersion:  lock.ForkVersion,
		Validators:   vals,
		Operators:    ops,
	}, nil
}

// isZeroProto returns true if the provided proto message is zero.
//
// Note this function is inefficient for the negative case (i.e. when the message is not zero)
// as it copies the input argument.
func isZeroProto(m proto.Message) bool {
	if m == nil {
		return false
	}

	clone := proto.Clone(m)
	proto.Reset(clone)

	return proto.Equal(m, clone)
}
