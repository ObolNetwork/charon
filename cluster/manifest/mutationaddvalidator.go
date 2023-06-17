// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package manifest

import (
	"bytes"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// NewGenValidators creates a new generate validators mutation.
func NewGenValidators(parent []byte, validators []*manifestpb.Validator) (*manifestpb.SignedMutation, error) {
	if err := verifyGenValidators(validators); err != nil {
		return nil, errors.Wrap(err, "verify validators")
	}

	if len(parent) != hashLen {
		return nil, errors.New("invalid parent hash")
	}

	valsAny, err := anypb.New(&manifestpb.ValidatorList{Validators: validators})
	if err != nil {
		return nil, errors.Wrap(err, "marshal validators")
	}

	return &manifestpb.SignedMutation{
		Mutation: &manifestpb.Mutation{
			Parent:    parent,
			Type:      string(TypeGenValidators),
			Timestamp: nowFunc(),
			Data:      valsAny,
		},
		// No signer or signature.
	}, nil
}

// verifyGenValidators validates the GenValidators list, ensuring validators are populated with valid addresses.
func verifyGenValidators(vals []*manifestpb.Validator) error {
	if len(vals) == 0 {
		return errors.New("no validators")
	}

	for _, validator := range vals {
		if _, err := from0xHex(validator.FeeRecipientAddress, 20); err != nil {
			return errors.Wrap(err, "validate fee recipient address")
		}
		if _, err := from0xHex(validator.WithdrawalAddress, 20); err != nil {
			return errors.Wrap(err, "validate withdrawal address")
		}
	}

	return nil
}

func transformGenValidators(c *manifestpb.Cluster, signed *manifestpb.SignedMutation) (*manifestpb.Cluster, error) {
	if err := verifyEmptySig(signed); err != nil {
		return c, errors.Wrap(err, "verify empty sig")
	}

	if MutationType(signed.Mutation.Type) != TypeGenValidators {
		return c, errors.New("invalid mutation type")
	}

	vals := new(manifestpb.ValidatorList)
	if err := signed.Mutation.Data.UnmarshalTo(vals); err != nil {
		return c, errors.Wrap(err, "unmarshal validators")
	}

	c.Validators = append(c.Validators, vals.Validators...)

	return c, nil
}

// NewAddValidators creates a new composite add validators mutation from the provided gen validators and node approvals.
func NewAddValidators(genValidators, nodeApprovals *manifestpb.SignedMutation) (*manifestpb.SignedMutation, error) {
	if MutationType(genValidators.Mutation.Type) != TypeGenValidators {
		return nil, errors.New("invalid gen validators mutation type")
	}

	if MutationType(nodeApprovals.Mutation.Type) != TypeNodeApprovals {
		return nil, errors.New("invalid node approvals mutation type")
	}

	dataAny, err := anypb.New(&manifestpb.SignedMutationList{
		Mutations: []*manifestpb.SignedMutation{genValidators, nodeApprovals},
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal signed mutation list")
	}

	return &manifestpb.SignedMutation{
		Mutation: &manifestpb.Mutation{
			Parent:    genValidators.Mutation.Parent,
			Type:      string(TypeAddValidators),
			Timestamp: nowFunc(),
			Data:      dataAny,
		},
		// Composite mutations have no signer or signature.
	}, nil
}

func transformAddValidators(c *manifestpb.Cluster, signed *manifestpb.SignedMutation) (*manifestpb.Cluster, error) {
	if err := verifyEmptySig(signed); err != nil {
		return c, errors.Wrap(err, "verify empty sig")
	}

	if MutationType(signed.Mutation.Type) != TypeAddValidators {
		return c, errors.New("invalid mutation type")
	}

	list := new(manifestpb.SignedMutationList)
	if err := signed.Mutation.Data.UnmarshalTo(list); err != nil {
		return c, errors.Wrap(err, "unmarshal signed mutation list")
	} else if len(list.Mutations) != 2 {
		return c, errors.New("invalid mutation list length")
	}

	genValidators := list.Mutations[0]
	nodeApprovals := list.Mutations[1]

	if MutationType(genValidators.Mutation.Type) != TypeGenValidators {
		return c, errors.New("invalid gen validators mutation type")
	}
	if !bytes.Equal(signed.Mutation.Parent, genValidators.Mutation.Parent) {
		return c, errors.New("invalid gen validators parent")
	}

	if MutationType(nodeApprovals.Mutation.Type) != TypeNodeApprovals {
		return c, errors.New("invalid node approvals mutation type")
	}

	genHash, err := Hash(genValidators)
	if err != nil {
		return c, errors.Wrap(err, "hash gen validators")
	}
	if !bytes.Equal(genHash, nodeApprovals.Mutation.Parent) {
		return c, errors.New("invalid node approvals parent")
	}

	c, err = Transform(c, genValidators)
	if err != nil {
		return c, errors.Wrap(err, "transform gen validators")
	}

	c, err = Transform(c, nodeApprovals)
	if err != nil {
		return c, errors.Wrap(err, "transform node approvals")
	}

	return c, nil
}
