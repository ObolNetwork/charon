// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"time"

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

// FeeRecipientFetchRequest represents the request body for fetching fee recipient registrations.
// Pubkeys is an optional list of validator public keys to filter the response.
// If empty, all validators in the cluster are returned.
type FeeRecipientFetchRequest struct {
	Pubkeys []string `json:"pubkeys"`
}

// FeeRecipientStatus represents the aggregation status for a validator's fee recipient registration.
type FeeRecipientStatus string

const (
	// FeeRecipientStatusUnknown indicates no partial signatures received.
	FeeRecipientStatusUnknown FeeRecipientStatus = "unknown"
	// FeeRecipientStatusPartial indicates some but not all partial signatures received.
	FeeRecipientStatusPartial FeeRecipientStatus = "partial"
	// FeeRecipientStatusComplete indicates enough partial signatures received to produce a complete signature.
	FeeRecipientStatusComplete FeeRecipientStatus = "complete"
)

// FeeRecipientValidatorStatus represents the aggregation status for a single validator.
type FeeRecipientValidatorStatus struct {
	Pubkey       string             `json:"pubkey"`
	Status       FeeRecipientStatus `json:"status"`
	Timestamp    time.Time          `json:"timestamp"`
	PartialCount int                `json:"partial_count"`
}

// FeeRecipientFetchResponse represents the response for fetching fee recipient registrations for a cluster.
type FeeRecipientFetchResponse struct {
	Registrations []*eth2api.VersionedSignedValidatorRegistration `json:"registrations"`
	Validators    []FeeRecipientValidatorStatus                   `json:"status"`
}
