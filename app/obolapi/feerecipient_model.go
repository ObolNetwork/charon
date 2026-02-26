// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
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

// PartialFeeRecipientResponsePartial represents a single partial registration in the response.
type PartialFeeRecipientResponsePartial struct {
	ShareIdx  int                           `json:"share_index"`
	Message   *eth2v1.ValidatorRegistration `json:"message"`
	Signature []byte                        `json:"signature"`
}

// PartialFeeRecipientResponse represents the response body when fetching partial fee recipient registrations.
type PartialFeeRecipientResponse struct {
	Partials []PartialFeeRecipientResponsePartial `json:"partial_registrations"`
}
