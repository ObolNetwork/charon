// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

type PartialDepositRequest struct {
	PartialDepositData []eth2p0.DepositData `json:"partial_deposit_data"`
}

// FullDepositResponse contains all partial signatures, public key, amounts and withdrawal credentials to construct
// a full deposit message for a validator.
// Signatures are ordered by share index.
type FullDepositResponse struct {
	PublicKey             string   `json:"public_key"`
	WithdrawalCredentials string   `json:"withdrawal_credentials"`
	Amounts               []Amount `json:"amounts"`
}

type Amount struct {
	Amount   string    `json:"amount"`
	Partials []Partial `json:"partials"`
}

type Partial struct {
	PartialPublicKey        string `json:"partial_public_key"`
	PartialDepositSignature string `json:"partial_deposit_signature"`
}
