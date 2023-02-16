// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cluster

// DepositData defines the deposit data to activate a validator.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
type DepositData struct {
	// PubKey is the validator public key.
	PubKey []byte `json:"pubkey"  ssz:"Bytes48" lock_hash:"0"`

	// WithdrawalCredentials included in the deposit.
	WithdrawalCredentials []byte `json:"withdrawal_credentials"  ssz:"Bytes32" lock_hash:"1"`

	// Amount is the amount in Gwei to be deposited.
	Amount int `json:"amount"  ssz:"uint64" lock_hash:"2"`

	// Signature is the BLS signature of the deposit message (above three fields).
	Signature []byte `json:"signature"  ssz:"Bytes96" lock_hash:"3"`
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
