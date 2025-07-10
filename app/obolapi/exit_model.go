// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// sszMaxExits is the maximum amount of exit messages in an array.
	sszMaxExits = 65536

	// sszLenPubKey is the length of a BLS validator public key.
	sszLenPubKey = 48
)

// PartialExitRequest represents the blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
// Signature is the EC signature of PartialExits's hash tree root done with the Charon node identity key.
type PartialExitRequest struct {
	UnsignedPartialExitRequest

	Signature []byte `json:"signature"`
}

// partialExitRequestDTO is PartialExitRequest, but for serialization on the wire.
type partialExitRequestDTO struct {
	UnsignedPartialExitRequest

	Signature string `json:"signature"`
}

func (p *PartialExitRequest) UnmarshalJSON(bytes []byte) error {
	var dto partialExitRequestDTO

	if err := json.Unmarshal(bytes, &dto); err != nil {
		//nolint: wrapcheck // caller will wrap this error
		return err
	}

	// a signature is 96 bytes long
	sigBytes, err := from0x(dto.Signature, 65)
	if err != nil {
		return err
	}

	p.UnsignedPartialExitRequest = dto.UnsignedPartialExitRequest
	p.Signature = sigBytes

	return nil
}

func (p PartialExitRequest) MarshalJSON() ([]byte, error) {
	dto := partialExitRequestDTO{
		UnsignedPartialExitRequest: p.UnsignedPartialExitRequest,
		Signature:                  fmt.Sprintf("%#x", p.Signature),
	}

	//nolint: wrapcheck // caller will wrap this error
	return json.Marshal(dto)
}

// UnsignedPartialExitRequest represents an unsigned blob of data sent to the Obol API server, which is stored in the backend awaiting
// aggregation.
type UnsignedPartialExitRequest struct {
	PartialExits PartialExits `json:"partial_exits"`
	ShareIdx     uint64       `json:"share_idx,omitempty"`
}

func (p UnsignedPartialExitRequest) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (p UnsignedPartialExitRequest) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p UnsignedPartialExitRequest) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	if err := p.PartialExits.HashTreeRootWith(hh); err != nil {
		return errors.Wrap(err, "hash tree root with")
	}

	hh.PutUint64(p.ShareIdx)

	hh.Merkleize(indx)

	return nil
}

// PartialExits is an array of ExitMessage that have been signed with a partial key.
type PartialExits []ExitBlob

func (p PartialExits) GetTree() (*ssz.Node, error) {
	hash, err := ssz.ProofTree(p)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return hash, nil
}

func (p PartialExits) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(p)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (p PartialExits) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	num := uint64(len(p))
	for _, pe := range p {
		if err := pe.HashTreeRootWith(hh); err != nil {
			return err
		}
	}

	hh.MerkleizeWithMixin(indx, num, sszMaxExits)

	return nil
}

// FullExitResponse contains all partial signatures, epoch and validator index to construct a full exit message for
// a validator.
// Signatures are ordered by share index.
type FullExitResponse struct {
	Epoch          string                `json:"epoch"`
	ValidatorIndex eth2p0.ValidatorIndex `json:"validator_index"`
	Signatures     []string              `json:"signatures"`
}

// FullExitAuthBlob represents the data required by Obol API to download the full exit blobs.
type FullExitAuthBlob struct {
	LockHash        []byte
	ValidatorPubkey []byte
	ShareIndex      uint64
}

func (f FullExitAuthBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(f)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (f FullExitAuthBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(f)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (f FullExitAuthBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(f.LockHash)

	if err := putBytesN(hh, f.ValidatorPubkey, sszLenPubKey); err != nil {
		return errors.Wrap(err, "validator pubkey ssz")
	}

	hh.PutUint64(f.ShareIndex)

	hh.Merkleize(indx)

	return nil
}

// ExitBlob is an exit message alongside its BLS12-381 hex-encoded signature.
type ExitBlob struct {
	PublicKey         string                     `json:"public_key,omitempty"`
	SignedExitMessage eth2p0.SignedVoluntaryExit `json:"signed_exit_message"`
}

func (e ExitBlob) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(e)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (e ExitBlob) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(e)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (e ExitBlob) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	pkBytes, err := from0x(e.PublicKey, 48) // public key is 48 bytes long
	if err != nil {
		return errors.Wrap(err, "pubkey to bytes")
	}

	// Field (0) 'PublicKey'
	hh.PutBytes(pkBytes)

	// Field (1) 'SignedExitMessage'
	if err := e.SignedExitMessage.HashTreeRootWith(hh); err != nil {
		return errors.Wrap(err, "signed exit message hash tree root")
	}

	hh.Merkleize(indx)

	return nil
}

// leftPad returns the byte slice left padded with zero to ensure a length of at least l.
func leftPad(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0x00}, b...)
	}

	return b
}

// putByteList appends b as a ssz fixed size byte array of length n.
func putBytesN(h ssz.HashWalker, b []byte, n int) error {
	if len(b) > n {
		return errors.New("bytes too long", z.Int("n", n), z.Int("l", len(b)))
	}

	h.PutBytes(leftPad(b, n))

	return nil
}

// from0x decodes hex-encoded data and expects it to be exactly of len(length).
// Accepts both 0x-prefixed strings or not.
func from0x(data string, length int) ([]byte, error) {
	if data == "" {
		return nil, errors.New("empty data")
	}

	b, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	} else if len(b) != length {
		return nil, errors.Wrap(err,
			"invalid hex length",
			z.Int("expect", length),
			z.Int("actual", len(b)),
		)
	}

	return b, nil
}
