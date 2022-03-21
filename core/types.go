// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"bytes"
	"encoding/hex"
	"fmt"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// DutyType enumerates the different types of duties.
type DutyType int

const (
	DutyUnknown = DutyType(iota)
	DutyAttester
	DutyProposer
	dutySentinal // Must always be last
)

func (d DutyType) Valid() bool {
	return d > DutyUnknown && d < dutySentinal
}

func (d DutyType) String() string {
	return map[DutyType]string{
		DutyUnknown:  "unknown",
		DutyAttester: "attester",
		DutyProposer: "proposer",
	}[d]
}

// AllDutyTypes returns a list of all valid duty types.
func AllDutyTypes() []DutyType {
	var resp []DutyType
	for i := DutyUnknown + 1; i.Valid(); i++ {
		resp = append(resp, i)
	}

	return resp
}

// Duty is the unit of work of the core workflow.
type Duty struct {
	// Slot is the Ethereum consensus layer slot.
	Slot int64
	// Type is the duty type performed in the slot.
	Type DutyType
}

func (d Duty) String() string {
	return fmt.Sprintf("%d/%s", d.Slot, d.Type)
}

const pkLen = 98 // "0x" + hex.Encode([48]byte) = 2+2*48

// PubKeyFromBytes returns a new public key from raw bytes.
func PubKeyFromBytes(bytes []byte) (PubKey, error) {
	pk := PubKey(fmt.Sprintf("%#x", bytes))
	if len(pk) != pkLen {
		return "", errors.New("invalid public key length")
	}

	return pk, nil
}

// PubKey is the DV root public key, the identifier of a validator in the core workflow.
// It is a hex formatted string, e.g. "0xb82bc680e...".
type PubKey string

// String returns a concise logging friendly version of the public key, e.g. "b82_97f".
func (k PubKey) String() string {
	if len(k) != pkLen {
		return "<invalid public key:" + string(k) + ">"
	}

	return string(k[2:5]) + "_" + string(k[94:97])
}

// Bytes returns the public key as raw bytes.
func (k PubKey) Bytes() ([]byte, error) {
	if len(k) != pkLen {
		return nil, errors.New("invalid public key length")
	}

	b, err := hex.DecodeString(string(k[2:]))
	if err != nil {
		return nil, errors.Wrap(err, "decode public key hex")
	}

	return b, nil
}

// ToETH2 returns the public key as an eth2 phase0 public key.
func (k PubKey) ToETH2() (eth2p0.BLSPubKey, error) {
	b, err := k.Bytes()
	if err != nil {
		return eth2p0.BLSPubKey{}, err
	}

	var resp eth2p0.BLSPubKey
	copy(resp[:], b)

	return resp, nil
}

// FetchArg contains the arguments required to fetch the duty data,
// it is the result of resolving duties at the start of an epoch.
type FetchArg []byte

// FetchArgSet is a set of fetch args, one per validator.
type FetchArgSet map[PubKey]FetchArg

// UnsignedData represents an unsigned duty data object.
type UnsignedData []byte

// UnsignedDataSet is a set of unsigned duty data objects, one per validator.
type UnsignedDataSet map[PubKey]UnsignedData

// AttestationData wraps the eth2 attestation data and adds the original duty.
// The original duty allows mapping the partial signed response from the VC
// backed to the validator pubkey via the aggregation bits field.
type AttestationData struct {
	Data eth2p0.AttestationData
	Duty eth2v1.AttesterDuty
}

// ParSignedData is a partially signed duty data.
// Partial refers to it being signed by a single share of the BLS threshold signing scheme.
type ParSignedData struct {
	// Data is the partially signed duty data received from VC.
	Data []byte
	// Signature of tbls share extracted from data.
	Signature []byte
	// ShareIdx of the tbls share.
	ShareIdx int
}

// ParSignedDataSet is a set of partially signed duty data objects, one per validator.
type ParSignedDataSet map[PubKey]ParSignedData

// AggSignedData is an aggregated signed duty data.
// Aggregated refers to it being signed by the aggregated BLS threshold signing scheme.
type AggSignedData struct {
	// Data is the signed duty data to be sent to beacon chain.
	Data []byte
	// Signature is the result of tbls aggregation and is inserted into the data.
	Signature []byte
}

func (a AggSignedData) Equal(b AggSignedData) bool {
	return bytes.Equal(a.Data, b.Data) && bytes.Equal(a.Signature, b.Signature)
}
