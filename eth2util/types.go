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
// We should maybe migrate to serialising as strings to aligned with eth2 spec at which
// point this type can be removed in favour of the go-eth2-client type.
type DataVersion string

const (
	DataVersionUnknown   DataVersion = ""
	DataVersionPhase0    DataVersion = "phase0"
	DataVersionAltair    DataVersion = "altair"
	DataVersionBellatrix DataVersion = "bellatrix"
	DataVersionCapella   DataVersion = "capella"
	DataVersionDeneb     DataVersion = "deneb"
)

// dataVersionValues maps DataVersion to the integer value used by go-eth2-client pre-v0.18.
var dataVersionValues = map[DataVersion]int{
	DataVersionPhase0:    0,
	DataVersionAltair:    1,
	DataVersionBellatrix: 2,
	DataVersionCapella:   3,
	DataVersionDeneb:     4,
}

// MarshalJSON marshals the DataVersion as a number equaled to the go-eth2-client
// pre-v0.18 integer value.
func (v DataVersion) MarshalJSON() ([]byte, error) {
	val, ok := dataVersionValues[v]
	if !ok {
		return nil, errors.New("unknown data version")
	}

	b, err := json.Marshal(val)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal data version")
	}

	return b, nil
}

// UnmarshalJSON unmarshals the DataVersion from strings or a number equaled to the go-eth2-client
// pre-v0.18 integer value.
func (v *DataVersion) UnmarshalJSON(input []byte) error {
	var intVal int
	if err := json.Unmarshal(input, &intVal); err != nil {
		return errors.Wrap(err, "failed to unmarshal data version")
	}

	for version, val := range dataVersionValues {
		if intVal == val {
			*v = version
			return nil
		}
	}

	return errors.New("unknown data version")
}

// ToUint64 returns the integer value used by go-eth2-client pre-v0.18.
func (v DataVersion) ToUint64() uint64 {
	return uint64(dataVersionValues[v])
}

// ToETH2 returns a eth2spec.DataVersion equivalent to the DataVersion.
func (v DataVersion) ToETH2() eth2spec.DataVersion {
	switch v {
	case DataVersionPhase0:
		return eth2spec.DataVersionPhase0
	case DataVersionAltair:
		return eth2spec.DataVersionAltair
	case DataVersionBellatrix:
		return eth2spec.DataVersionBellatrix
	case DataVersionCapella:
		return eth2spec.DataVersionCapella
	case DataVersionDeneb:
		return eth2spec.DataVersionDeneb
	default:
		return eth2spec.DataVersion(0)
	}
}

// String returns the string representation of the DataVersion.
func (v DataVersion) String() string {
	_, ok := dataVersionValues[v]
	if !ok {
		return "unknown"
	}

	return string(v)
}

// DataVersionFromUint64 returns the DataVersion from the integer value used by go-eth2-client pre-v0.18.
func DataVersionFromUint64(val uint64) (DataVersion, error) {
	for version, v := range dataVersionValues {
		if val == uint64(v) {
			return version, nil
		}
	}

	return DataVersionUnknown, errors.New("unknown data version")
}

// DataVersionFromETH2 returns the DataVersion from the eth2spec.DataVersion.
func DataVersionFromETH2(version eth2spec.DataVersion) (DataVersion, error) {
	switch version {
	case eth2spec.DataVersionPhase0:
		return DataVersionPhase0, nil
	case eth2spec.DataVersionAltair:
		return DataVersionAltair, nil
	case eth2spec.DataVersionBellatrix:
		return DataVersionBellatrix, nil
	case eth2spec.DataVersionCapella:
		return DataVersionCapella, nil
	case eth2spec.DataVersionDeneb:
		return DataVersionDeneb, nil
	default:
		return DataVersionUnknown, errors.New("unknown data version")
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
