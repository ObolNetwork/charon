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

// Definition defines an intended charon cluster configuration.
type Definition struct {
	// Name is an optional cosmetic identifier
	Name string

	// UUID is a random unique identifier
	UUID string

	// Version is the schema version of this definition.
	Version string

	// NumValidators is the number of DVs (n*32ETH) to be created in the cluster lock file.
	NumValidators int

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int

	// FeeRecipientAddress Ethereum address.
	FeeRecipientAddress string

	// WithdrawalAddress Ethereum address.
	WithdrawalAddress string

	// DKGAlgorithm to use for key generation.
	DKGAlgorithm string

	// ForkVersion defines the cluster's beacon chain hex fork definitionVersion (network/chain identifier).
	ForkVersion string

	// Operators define the charon nodes in the cluster and their operators.
	Operators []Operator

	// OperatorSignatures are EIP712 signatures of the definition hash by each operator Ethereum address.
	// Fully populated operator signatures results in "sealed" definition ready for use in DKG.
	OperatorSignatures [][]byte
}

// Operator identifies a charon node and its operator.
type Operator struct {
	// Address is the Ethereum address identifying the operator.
	Address string `json:"address"`

	// ENR identifies the charon node.
	ENR string `json:"enr"`

	// Nonce is incremented each time the ENR is signed.
	Nonce int `json:"nonce"`

	// ENRSignature is a EIP712 signature of the ENR by the Address, authorising the charon node to act on behalf of the operator in the cluster.
	ENRSignature []byte `json:"enr_signature"`
}

// Lock extends the cluster config Definition with bls threshold public keys and checksums.
type Lock struct {
	// Definition is embedded and extended by Lock.
	Definition

	// Validators are the distributed validators (n*32ETH) managed by the cluster.
	Validators []DistValidator

	// SignatureAggregate is the bls aggregate signature of the lock hash signed by each DV pubkey.
	// It acts as an attestation by all the distributed validators of the charon cluster they are part of.
	SignatureAggregate []byte
}

// DistValidator is a distributed validator (1x32ETH) managed by the cluster.
type DistValidator struct {
	// PubKey is the root distributed public key.
	PubKey string `json:"distributed_public_key"`

	// Verifiers are the public shares.
	Verifiers [][]byte `json:"threshold_verifiers"`

	// FeeRecipientAddress Ethereum address override for this validator, defaults to definition withdrawal address.
	FeeRecipientAddress string `json:"fee_recipient_address,omitempty"`
}
