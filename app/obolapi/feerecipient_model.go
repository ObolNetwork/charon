// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"encoding/json"
	"fmt"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"

	"github.com/obolnetwork/charon/tbls"
)

// PartialRegistration represents a partial builder registration with a partial BLS signature.
// The signature is encoded as a 0x-prefixed hex string on the wire.
type PartialRegistration struct {
	Message   *eth2v1.ValidatorRegistration
	Signature tbls.Signature
}

// partialRegistrationDTO is the wire representation of PartialRegistration.
type partialRegistrationDTO struct {
	Message   *eth2v1.ValidatorRegistration `json:"message"`
	Signature string                        `json:"signature"`
}

func (p PartialRegistration) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // caller will wrap
	return json.Marshal(partialRegistrationDTO{
		Message:   p.Message,
		Signature: fmt.Sprintf("%#x", p.Signature),
	})
}

func (p *PartialRegistration) UnmarshalJSON(data []byte) error {
	var dto partialRegistrationDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		//nolint:wrapcheck // caller will wrap
		return err
	}

	sigBytes, err := from0x(dto.Signature, 96)
	if err != nil {
		return err
	}

	p.Message = dto.Message
	copy(p.Signature[:], sigBytes)

	return nil
}

// PartialFeeRecipientRequest represents the request body for posting partial builder registrations.
type PartialFeeRecipientRequest struct {
	PartialRegistrations []PartialRegistration `json:"partial_registrations"`
}

// FeeRecipientFetchRequest represents the request body for fetching builder registrations.
// Pubkeys is an optional list of validator public keys to filter the response.
// If empty, all validators in the cluster are returned.
type FeeRecipientFetchRequest struct {
	Pubkeys []string `json:"pubkeys"`
}

// FeeRecipientPartialSig is a partial BLS signature with its share index.
// The signature is encoded as a 0x-prefixed hex string on the wire.
type FeeRecipientPartialSig struct {
	ShareIndex int
	Signature  tbls.Signature
}

// feeRecipientPartialSigDTO is the wire representation of FeeRecipientPartialSig.
type feeRecipientPartialSigDTO struct {
	ShareIndex int    `json:"share_index"`
	Signature  string `json:"signature"`
}

func (f *FeeRecipientPartialSig) UnmarshalJSON(data []byte) error {
	var dto feeRecipientPartialSigDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		//nolint:wrapcheck // caller will wrap
		return err
	}

	sigBytes, err := from0x(dto.Signature, 96)
	if err != nil {
		return err
	}

	f.ShareIndex = dto.ShareIndex
	copy(f.Signature[:], sigBytes)

	return nil
}

func (f FeeRecipientPartialSig) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // caller will wrap
	return json.Marshal(feeRecipientPartialSigDTO{
		ShareIndex: f.ShareIndex,
		Signature:  fmt.Sprintf("%#x", f.Signature),
	})
}

// FeeRecipientBuilderRegistration is one registration group sharing the same message,
// with partial signatures from individual operators.
type FeeRecipientBuilderRegistration struct {
	Message           *eth2v1.ValidatorRegistration `json:"message"`
	PartialSignatures []FeeRecipientPartialSig      `json:"partial_signatures"`
	Quorum            bool                          `json:"quorum"`
}

// FeeRecipientValidator is the per-validator entry in the fetch response.
type FeeRecipientValidator struct {
	Pubkey               string                            `json:"pubkey"`
	BuilderRegistrations []FeeRecipientBuilderRegistration `json:"builder_registrations"`
}

// FeeRecipientFetchResponse is the response for the fee recipient fetch endpoint.
type FeeRecipientFetchResponse struct {
	Validators []FeeRecipientValidator `json:"validators"`
}
