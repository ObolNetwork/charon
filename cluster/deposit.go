// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// DepositData defines the deposit data to activate a validator.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
type DepositData struct {
	// PubKey is the validator public key.
	PubKey []byte `json:"pubkey" lock_hash:"0" ssz:"Bytes48"`

	// WithdrawalCredentials included in the deposit.
	WithdrawalCredentials []byte `json:"withdrawal_credentials" lock_hash:"1" ssz:"Bytes32"`

	// Amount is the amount in Gwei to be deposited.
	Amount int `json:"amount" lock_hash:"2" ssz:"uint64"`

	// Signature is the BLS signature of the deposit message (above three fields).
	Signature []byte `json:"signature" lock_hash:"3" ssz:"Bytes96"`
}

// depositDataJSON is the json formatter of DepositData.
type depositDataJSON struct {
	PubKey                ethHex `json:"pubkey"`
	WithdrawalCredentials ethHex `json:"withdrawal_credentials"`
	Amount                int    `json:"amount,string"`
	Signature             ethHex `json:"signature"`
}

// depositDataToJSON converts DepositData to depositDataJSON.
func depositDataToJSON(d DepositData) depositDataJSON {
	return depositDataJSON{
		PubKey:                d.PubKey,
		WithdrawalCredentials: d.WithdrawalCredentials,
		Amount:                d.Amount,
		Signature:             d.Signature,
	}
}

// depositDataFromJSON converts depositDataJSON to DepositData.
func depositDataFromJSON(d depositDataJSON) DepositData {
	return DepositData{
		PubKey:                d.PubKey,
		WithdrawalCredentials: d.WithdrawalCredentials,
		Amount:                d.Amount,
		Signature:             d.Signature,
	}
}

// VerifyDepositAmounts verifies various conditions about partial deposits rules.
func VerifyDepositAmounts(amounts []eth2p0.Gwei) error {
	if len(amounts) == 0 {
		return nil
	}

	const minSingleDepositAmountGwei = 1000000000
	const maxTotalDepositAmountGwei = 32000000000

	var sum eth2p0.Gwei
	for _, amount := range amounts {
		if amount < minSingleDepositAmountGwei {
			return errors.New("each partial deposit amount must be greater than 1ETH", z.U64("amount", uint64(amount)))
		}
		sum += amount
	}

	if sum > eth2p0.Gwei(maxTotalDepositAmountGwei) {
		return errors.New("sum of partial deposit amounts must sum up to 32ETH", z.U64("sum", uint64(sum)))
	}

	return nil
}

// DepositAmountsFromIntSlice converts amounts from []int to []eth2p0.Gwei.
// For verification, please see VerifyDepositAmounts().
func DepositAmountsFromIntSlice(amounts []int) []eth2p0.Gwei {
	if amounts == nil {
		return nil
	}

	gweiAmounts := make([]eth2p0.Gwei, len(amounts))
	for i, amount := range amounts {
		gweiAmounts[i] = eth2p0.Gwei(amount)
	}

	return gweiAmounts
}
