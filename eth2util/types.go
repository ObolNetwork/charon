// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"encoding/json"
	"strings"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// DataVersion defines the spec version of the data in a response.
// The number values match those of go-eth2-client v0.17 and earlier releases.
// This allows us to be compatible with those older versions when serialising as numbers.
//
// We should migrate to serialising as strings to aligned with eth2 spec at which
// point this type can be removed in favour of the go-eth2-client type.
type DataVersion eth2spec.DataVersion

const (
	DataVersionPhase0    DataVersion = 0
	DataVersionAltair    DataVersion = 1
	DataVersionBellatrix DataVersion = 2
	DataVersionCapella   DataVersion = 3
	DataVersionDeneb     DataVersion = 4
)

// String returns the string representation of the DataVersion.
func (v DataVersion) String() string {
	switch v {
	case DataVersionPhase0:
		return "phase0"
	case DataVersionAltair:
		return "altair"
	case DataVersionBellatrix:
		return "bellatrix"
	case DataVersionCapella:
		return "capella"
	case DataVersionDeneb:
		return "deneb"
	default:
		return "unknown"
	}
}

// SignedEpoch represents signature of corresponding epoch.
type SignedEpoch struct {
	Epoch     eth2p0.Epoch
	Signature eth2p0.BLSSignature
}

// GetTree ssz hashes the SignedEpoch object.
func (s SignedEpoch) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s) //nolint:wrapcheck
}

// HashTreeRoot ssz hashes the SignedEpoch object.
func (s SignedEpoch) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the epoch from SignedEpoch.
func (s SignedEpoch) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutUint64(uint64(s.Epoch))

	hh.Merkleize(indx)

	return nil
}

// legacySignature marshals to []byte to remain compatible with v0.16.
type legacySignature [96]byte

// MarshalJSON marshalls legacy []byte signatures to remain compatible with v0.16.
// Migrate to eth2p0.BLSSignature in v0.18.
func (s SignedEpoch) MarshalJSON() ([]byte, error) {
	rawSig, err := json.Marshal(legacySignature(s.Signature))
	if err != nil {
		return nil, errors.Wrap(err, "marshal legacy signed epoch signature")
	}

	resp, err := json.Marshal(signedEpochJSON{
		Epoch:     s.Epoch,
		Signature: rawSig,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal signed epoch")
	}

	return resp, nil
}

// UnmarshalJSON unmarshalls both legacy []byte as well as 0xhex signatures.
// Remove support for legacy []byte in v0.19.
func (s *SignedEpoch) UnmarshalJSON(b []byte) error {
	var resp signedEpochJSON
	if err := json.Unmarshal(b, &resp); err != nil {
		return errors.Wrap(err, "unmarshal signed epoch")
	}
	s.Epoch = resp.Epoch

	if strings.HasPrefix(string(resp.Signature), "\"0x") {
		if err := json.Unmarshal(resp.Signature, &s.Signature); err != nil {
			return errors.Wrap(err, "unmarshal signed epoch signature")
		}

		return nil
	}

	var sig []byte
	if err := json.Unmarshal(resp.Signature, &sig); err != nil {
		return errors.Wrap(err, "unmarshal legacy signed epoch signature")
	} else if len(sig) != 96 {
		return errors.New("invalid legacy signed epoch signature length")
	}

	s.Signature = eth2p0.BLSSignature(sig)

	return nil
}

// signedEpochJSON supports both legacy []byte and 0xhex signatures
//
// TODO(corver): Revert to eth2p0.BLSSignature in v0.19.
type signedEpochJSON struct {
	Epoch     eth2p0.Epoch    `json:"epoch"`
	Signature json.RawMessage `json:"signature"`
}
