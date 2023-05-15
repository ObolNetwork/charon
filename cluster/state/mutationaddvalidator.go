// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
)

func NewAddValidators(parent [32]byte, validators []Validator) SignedMutation {
	return SignedMutation{
		Mutation: Mutation{
			Parent:    parent,
			Type:      TypeAddValidators,
			Timestamp: nowFunc(),
			Data:      addValidators{Validators: validators},
		},
		// No signer or signature.
	}
}

type addValidators struct {
	Validators []Validator `ssz:"CompositeList[65536],toSSZ"`
}

func (v addValidators) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(validatorsToJSON(v.Validators))
	if err != nil {
		return nil, errors.Wrap(err, "marshal validators")
	}

	return b, nil
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

	c.Validators = append(c.Validators, add.Validators...)

	return c, nil
}
