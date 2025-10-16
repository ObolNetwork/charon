// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
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
	Amount   uint64    `json:"amount"`
	Partials []Partial `json:"partials"`
}

type Partial struct {
	PartialPublicKey        string `json:"partial_public_key"`
	PartialDepositSignature string `json:"partial_deposit_signature"`
}

// FullDepositAuthBlob represents the data required by Obol API to download the full deposit blobs.
type FullDepositAuthBlob struct {
	LockHash        []byte
	ValidatorPubkey []byte
	ShareIndex      uint64
}

func (f FullDepositAuthBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(f)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (f FullDepositAuthBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(f)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (f FullDepositAuthBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(f.LockHash)

	if err := putBytesN(hh, f.ValidatorPubkey, sszLenPubKey); err != nil {
		return errors.Wrap(err, "validator pubkey ssz")
	}

	hh.PutUint64(f.ShareIndex)

	hh.Merkleize(indx)

	return nil
}
