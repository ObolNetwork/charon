// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

// Code generated by genssz. DO NOT EDIT.

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// HashTreeRootWith ssz hashes the validatorSSZ object with a hasher
func (z validatorSSZ) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'PubKey' ssz:"ByteList[256]"
	err = putByteList(hw, []byte(z.PubKey[:]), 256, "PubKey")
	if err != nil {
		return err
	}

	// Field 1: 'PubShares' ssz:"CompositeList[65536]"
	{
		listIdx := hw.Index()
		for _, item := range z.PubShares {
			err = item.HashTreeRootWith(hw)
			if err != nil {
				return err
			}
		}

		hw.MerkleizeWithMixin(listIdx, uint64(len(z.PubShares)), uint64(65536))
	}

	// Field 2: 'FeeRecipientAddress' ssz:"Bytes20"
	err = putBytesN(hw, []byte(z.FeeRecipientAddress[:]), 20)
	if err != nil {
		return err
	}

	// Field 3: 'WithdrawalAddress' ssz:"Bytes20"
	err = putBytesN(hw, []byte(z.WithdrawalAddress[:]), 20)
	if err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the sszPubkey object with a hasher
func (p sszPubkey) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'Pubkey' ssz:"ByteList[256]"
	err = putByteList(hw, []byte(p.Pubkey[:]), 256, "Pubkey")
	if err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the genValidators object with a hasher
func (v genValidators) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'Validators' ssz:"CompositeList[65536]"
	{
		listIdx := hw.Index()
		for _, item := range v.Validators {
			err = item.toSSZ().HashTreeRootWith(hw)
			if err != nil {
				return err
			}
		}

		hw.MerkleizeWithMixin(listIdx, uint64(len(v.Validators)), uint64(65536))
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the addValidators object with a hasher
func (v addValidators) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'GenValidators' ssz:"Composite"
	err = v.GenValidators.HashTreeRootWith(hw)
	if err != nil {
		return err
	}

	// Field 1: 'NodeApprovals' ssz:"Composite"
	err = v.NodeApprovals.HashTreeRootWith(hw)
	if err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the nodeApprovals object with a hasher
func (a nodeApprovals) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'Approvals' ssz:"CompositeList[256]"
	{
		listIdx := hw.Index()
		for _, item := range a.Approvals {
			err = item.HashTreeRootWith(hw)
			if err != nil {
				return err
			}
		}

		hw.MerkleizeWithMixin(listIdx, uint64(len(a.Approvals)), uint64(256))
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the Mutation object with a hasher
func (m Mutation) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'Parent' ssz:"Bytes32"
	err = putBytesN(hw, []byte(m.Parent[:]), 32)
	if err != nil {
		return err
	}

	// Field 1: 'Type' ssz:"ByteList[64]"
	err = putByteList(hw, []byte(m.Type[:]), 64, "Type")
	if err != nil {
		return err
	}

	// Field 2: 'Timestamp' ssz:"uint64"
	hw.PutUint64(uint64(m.Timestamp.Unix()))

	// Field 3: 'Data' ssz:"Composite"
	err = m.Data.HashTreeRootWith(hw)
	if err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// HashTreeRootWith ssz hashes the SignedMutation object with a hasher
func (m SignedMutation) HashTreeRootWith(hw ssz.HashWalker) (err error) {
	indx := hw.Index()

	// Field 0: 'Mutation' ssz:"Composite"
	err = m.Mutation.HashTreeRootWith(hw)
	if err != nil {
		return err
	}

	// Field 1: 'Signer' ssz:"ByteList[256]"
	err = putByteList(hw, []byte(m.Signer[:]), 256, "Signer")
	if err != nil {
		return err
	}

	// Field 2: 'Signature' ssz:"ByteList[256]"
	err = putByteList(hw, []byte(m.Signature[:]), 256, "Signature")
	if err != nil {
		return err
	}

	hw.Merkleize(indx)

	return nil
}

// putByteList appends a ssz byte list.
// See reference: github.com/attestantio/go-eth2-client/spec/bellatrix/executionpayload_encoding.go:277-284.
func putByteList(h ssz.HashWalker, b []byte, limit int, field string) error {
	elemIndx := h.Index()
	byteLen := len(b)
	if byteLen > limit {
		return errors.Wrap(ssz.ErrIncorrectListSize, "put byte list", z.Str("field", field))
	}
	h.AppendBytes32(b)
	h.MerkleizeWithMixin(elemIndx, uint64(byteLen), uint64(limit+31)/32)

	return nil
}

// putByteList appends b as a ssz fixed size byte array of length n.
func putBytesN(h ssz.HashWalker, b []byte, n int) error {
	if len(b) > n {
		return errors.New("bytes too long", z.Int("n", n), z.Int("l", len(b)))
	}

	h.PutBytes(leftPad(b, n))

	return nil
}

// leftPad returns the byte slice left padded with zero to ensure a length of at least l.
func leftPad(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0x00}, b...)
	}

	return b
}
