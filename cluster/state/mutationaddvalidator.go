// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
)

// NewGenValidators creates a new generate validators mutation.
func NewGenValidators(parent [32]byte, validators []Validator) (SignedMutation, error) {
	genVals := genValidators{Validators: validators}

	if err := genVals.Verify(); err != nil {
		return SignedMutation{}, errors.Wrap(err, "verify validators")
	}

	return SignedMutation{
		Mutation: Mutation{
			Parent:    parent,
			Type:      TypeGenValidators,
			Timestamp: nowFunc(),
			Data:      genVals,
		},
		// No signer or signature.
	}, nil
}

// genValidators is a wrapper around []Validator to allow it to be marshaled to JSON and SSZ.
type genValidators struct {
	Validators []Validator `ssz:"CompositeList[65536],toSSZ"`
}

func (v genValidators) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(validatorsToJSON(v.Validators))
	if err != nil {
		return nil, errors.Wrap(err, "marshal validators")
	}

	return b, nil
}

// Verify validates the gen validators mutation, ensuring validators are populated with valid addresses.
// This allows ToSSZ to be called without error.
func (v genValidators) Verify() error {
	if len(v.Validators) == 0 {
		return errors.New("no validators")
	}

	for _, validator := range v.Validators {
		if _, err := from0xHex(validator.FeeRecipientAddress, 20); err != nil {
			return errors.Wrap(err, "validate fee recipient address")
		}
		if _, err := from0xHex(validator.WithdrawalAddress, 20); err != nil {
			return errors.Wrap(err, "validate withdrawal address")
		}
	}

	return nil
}

func transformGenValidators(c Cluster, signed SignedMutation) (Cluster, error) {
	if err := verifyEmptySig(signed); err != nil {
		return c, errors.Wrap(err, "verify empty sig")
	}

	if signed.Mutation.Type != TypeGenValidators {
		return c, errors.New("invalid mutation type")
	}

	gen, ok := signed.Mutation.Data.(genValidators)
	if !ok {
		return c, errors.New("invalid gen validators data")
	}

	c.Validators = append(c.Validators, gen.Validators...)

	return c, nil
}

// NewAddValidators creates a new composite add validators mutation from the provided gen validators and node approvals.
func NewAddValidators(genValidators, nodeApprovals SignedMutation) (SignedMutation, error) {
	if genValidators.Mutation.Type != TypeGenValidators {
		return SignedMutation{}, errors.New("invalid gen validators mutation type")
	}

	if nodeApprovals.Mutation.Type != TypeNodeApprovals {
		return SignedMutation{}, errors.New("invalid node approvals mutation type")
	}

	return SignedMutation{
		Mutation: Mutation{
			Parent:    genValidators.Mutation.Parent,
			Type:      TypeAddValidators,
			Timestamp: nowFunc(),
			Data:      addValidators{GenValidators: genValidators, NodeApprovals: nodeApprovals},
		},
		// Composite mutations have no signer or signature.
	}, nil
}

type addValidators struct {
	GenValidators SignedMutation `ssz:"Composite"`
	NodeApprovals SignedMutation `ssz:"Composite"`
}

func (a addValidators) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(addValidatorsJSON(a))
	if err != nil {
		return nil, errors.Wrap(err, "marshal add validators")
	}

	return b, nil
}

type addValidatorsJSON struct {
	GenValidators SignedMutation `json:"gen_validators"`
	NodeApprovals SignedMutation `json:"node_approvals"`
}

func transformAddValidators(c Cluster, signed SignedMutation) (Cluster, error) {
	if err := verifyEmptySig(signed); err != nil {
		return c, errors.Wrap(err, "verify empty sig")
	}

	if signed.Mutation.Type != TypeAddValidators {
		return c, errors.New("invalid mutation type")
	}

	add, ok := signed.Mutation.Data.(addValidators)
	if !ok {
		return c, errors.New("invalid add validators data")
	}

	if add.GenValidators.Mutation.Type != TypeGenValidators {
		return c, errors.New("invalid gen validators mutation type")
	}
	if signed.Mutation.Parent != add.GenValidators.Mutation.Parent {
		return c, errors.New("invalid gen validators parent")
	}

	if add.NodeApprovals.Mutation.Type != TypeNodeApprovals {
		return c, errors.New("invalid node approvals mutation type")
	}

	genHash, err := add.GenValidators.Hash()
	if err != nil {
		return c, errors.Wrap(err, "hash gen validators")
	}
	if add.NodeApprovals.Mutation.Parent != genHash {
		return c, errors.New("invalid node approvals parent")
	}

	c, err = add.GenValidators.Transform(c)
	if err != nil {
		return c, errors.Wrap(err, "transform gen validators")
	}

	c, err = add.NodeApprovals.Transform(c)
	if err != nil {
		return c, errors.Wrap(err, "transform node approvals")
	}

	return c, nil
}
