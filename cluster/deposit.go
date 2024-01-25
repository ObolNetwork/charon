// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

// DepositData defines the deposit data to activate a validator.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
type DepositData struct {
	// PubKey is the validator public key.
	PubKey []byte `json:"pubkey" lock_hash:"0" ssz:"Bytes48"`

	// WithdrawalCredentials included in the deposit.
	WithdrawalCredentials []byte `json:"withdrawal_credentials" lock_hash:"1" ssz:"Bytes32"`

	// Amount is the amount in Gwei to be deposited [1ETH..32ETH].
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

// firstDepositDataOrDefault returns the first DepositData element or a default instance.
// For backward compatibility with versions prior to v1.8.
func firstDepositDataOrDefault(dd []DepositData) DepositData {
	if len(dd) == 0 {
		return DepositData{}
	}

	return dd[0]
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

// depositDataArrayToJSON converts []DepositData to []depositDataJSON.
func depositDataArrayToJSON(dd []DepositData) []depositDataJSON {
	if dd == nil {
		return nil
	}

	array := make([]depositDataJSON, len(dd))
	for i, d := range dd {
		array[i] = depositDataToJSON(d)
	}

	return array
}

// depositDataArrayFromJSON converts []depositDataJSON to []DepositData.
func depositDataArrayFromJSON(dd []depositDataJSON) []DepositData {
	if dd == nil {
		return nil
	}

	array := make([]DepositData, len(dd))
	for i, d := range dd {
		array[i] = depositDataFromJSON(d)
	}

	return array
}
