// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"

	"github.com/obolnetwork/charon/tbls"
)

// PartialRegistration represents a partial builder registration with a partial BLS signature.
type PartialRegistration struct {
	Message   *eth2v1.ValidatorRegistration `json:"message"`
	Signature tbls.Signature                `json:"signature"`
}

// PartialFeeRecipientRequest represents the request body for posting partial fee recipient registrations.
type PartialFeeRecipientRequest struct {
	PartialRegistrations []PartialRegistration `json:"partial_registrations"`
}

// FeeRecipientValidatorStatus represents the aggregation status for a single validator.
type FeeRecipientValidatorStatus struct {
	Pubkey       string `json:"pubkey"`
	Status       string `json:"status"` // "pending" or "complete"
	PartialCount int    `json:"partial_count"`
}

// FeeRecipientFetchResponse represents the response for fetching fee recipient registrations for a cluster.
type FeeRecipientFetchResponse struct {
	Registrations []*eth2api.VersionedSignedValidatorRegistration `json:"registrations"`
	Validators    []FeeRecipientValidatorStatus                   `json:"status"`
}
