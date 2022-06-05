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
	// DutyType enums MUST not change, it will break backwards compatibility.

	DutyUnknown   DutyType = 0
	DutyProposer  DutyType = 1
	DutyAttester  DutyType = 2
	DutyRandao    DutyType = 3
	DutyExit      DutyType = 4
	DutySignature DutyType = 5
	// Only ever append new types here...

	dutySentinel DutyType = 6 // Must always be last
)

func (d DutyType) Valid() bool {
	return d > DutyUnknown && d < dutySentinel
}

func (d DutyType) String() string {
	return map[DutyType]string{
		DutyUnknown:   "unknown",
		DutyAttester:  "attester",
		DutyProposer:  "proposer",
		DutyRandao:    "randao",
		DutyExit:      "exit",
		DutySignature: "signature",
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

// NewAttesterDuty returns a new attester duty. It is a convenience function that is
// slightly more readable and concise than the struct literal equivalent:
//   core.Duty{Slot: slot, Type: core.DutyAttester}
//   vs
//   core.NewAttesterDuty(slot)
func NewAttesterDuty(slot int64) Duty {
	return Duty{
		Slot: slot,
		Type: DutyAttester,
	}
}

// NewRandaoDuty returns a new randao duty. It is a convenience function that is
// slightly more readable and concise than the struct literal equivalent:
//   core.Duty{Slot: slot, Type: core.DutyRandao}
//   vs
//   core.NewRandaoDuty(slot)
func NewRandaoDuty(slot int64) Duty {
	return Duty{
		Slot: slot,
		Type: DutyRandao,
	}
}

// NewProposerDuty returns a new proposer duty. It is a convenience function that is
// slightly more readable and concise than the struct literal equivalent:
//   core.Duty{Slot: slot, Type: core.DutyProposer}
//   vs
//   core.NewProposerDuty(slot)
func NewProposerDuty(slot int64) Duty {
	return Duty{
		Slot: slot,
		Type: DutyProposer,
	}
}

const (
	pkLen  = 98 // "0x" + hex.Encode([48]byte) = 2+2*48
	sigLen = 96
)

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

// Signature is a BLS12-381 Signature.
type Signature []byte

// ToETH2 returns the signature as an eth2 phase0 BLSSignature.
func (s Signature) ToETH2() eth2p0.BLSSignature {
	var sig eth2p0.BLSSignature
	copy(sig[:], s)

	return sig
}

// SigFromETH2 returns a new signature from eth2 phase0 BLSSignature.
func SigFromETH2(sig eth2p0.BLSSignature) Signature {
	s := make(Signature, sigLen)
	copy(s, sig[:])

	return s
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
type ParSignedData interface {
	// Signature returns the partial signature.
	Signature() Signature
	// DataRoot returns the eth2 data root of te duty data used to create the signature.
	DataRoot() (eth2p0.Root, error)
	// ShareIdx returns the threshold BLS share index of the partial signature.
	ShareIdx() int
	// MarshalData return json marshalled duty data associated with the signature.
	MarshalData() ([]byte, error)
	// AggSign returns the aggregated signed duty data by replacing the partial signature
	// with the provided aggregated signature.
	AggSign(aggregate Signature) (AggSignedData, error)
}

// ParSignedDataSet is a set of partially signed duty data objects, one per validator.
type ParSignedDataSet map[PubKey]ParSignedData

// AggSignedData is an aggregated signed duty data.
// Aggregated refers to it being signed by the aggregated BLS threshold signing scheme.
type AggSignedData struct {
	// Data is the signed duty data to be sent to beacon chain.
	Data []byte
	// Signature is the result of tbls aggregation and is inserted into the data.
	Signature Signature
}

func (a AggSignedData) Equal(b AggSignedData) bool {
	return bytes.Equal(a.Data, b.Data) && bytes.Equal(a.Signature, b.Signature)
}
