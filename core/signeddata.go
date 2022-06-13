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
	"encoding/json"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	_ SignedData = VersionedSignedBeaconBlock{}
	_ SignedData = Attestation{}
	_ SignedData = Signature{}
	_ SignedData = SignedVoluntaryExit{}
)

// SigFromETH2 returns a new signature from eth2 phase0 BLSSignature.
func SigFromETH2(sig eth2p0.BLSSignature) Signature {
	s := make(Signature, sigLen)
	copy(s, sig[:])

	return s
}

// NewPartialSignature is a convenience function that returns a new partially signature.
func NewPartialSignature(sig Signature, shareIdx int) ParSignedData2 {
	return ParSignedData2{
		SignedData: sig,
		ShareIdx:   shareIdx,
	}
}

// Signature is a BLS12-381 Signature. It implements SignedData.
type Signature []byte

func (s Signature) Signature() Signature {
	return s
}

func (Signature) SetSignature(sig Signature) (SignedData, error) {
	return sig, nil
}

func (s Signature) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal([]byte(s))
	if err != nil {
		return nil, errors.Wrap(err, "marshal signature")
	}

	return resp, nil
}

func (s *Signature) UnmarshalJSON(b []byte) error {
	var resp []byte
	if err := json.Unmarshal(b, &resp); err != nil {
		return errors.Wrap(err, "unmarshal signature")
	}

	*s = resp

	return nil
}

// ToETH2 returns the signature as an eth2 phase0 BLSSignature.
func (s Signature) ToETH2() eth2p0.BLSSignature {
	var sig eth2p0.BLSSignature
	copy(sig[:], s)

	return sig
}

// NewVersionedSignedBeaconBlock validates and returns a new wrapped VersionedSignedBeaconBlock.
func NewVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock) (VersionedSignedBeaconBlock, error) {
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no phase0 block")
		}
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no altair block")
		}
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedSignedBeaconBlock{}, errors.New("no bellatrix block")
		}
	default:
		return VersionedSignedBeaconBlock{}, errors.New("unknown version")
	}

	return VersionedSignedBeaconBlock{VersionedSignedBeaconBlock: *block}, nil
}

// NewPartialVersionedSignedBeaconBlock is a convenience function that returns a new partial signed block.
func NewPartialVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock, shareIdx int) (ParSignedData2, error) {
	wrap, err := NewVersionedSignedBeaconBlock(block)
	if err != nil {
		return ParSignedData2{}, err
	}

	return ParSignedData2{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedBeaconBlock is a signed versioned beacon block and implements SignedData.
type VersionedSignedBeaconBlock struct {
	spec.VersionedSignedBeaconBlock // Could subtype instead of embed, but aligning with Attestation that cannot subtype.
}

func (b VersionedSignedBeaconBlock) Signature() Signature {
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case spec.DataVersionPhase0:
		return SigFromETH2(b.Phase0.Signature)
	case spec.DataVersionAltair:
		return SigFromETH2(b.Altair.Signature)
	case spec.DataVersionBellatrix:
		return SigFromETH2(b.Bellatrix.Signature)
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBeaconBlock`.
	}
}

func (b VersionedSignedBeaconBlock) SetSignature(sig Signature) (SignedData, error) {
	var resp VersionedSignedBeaconBlock
	if err := cloneSignedData(b, &resp); err != nil {
		return nil, err
	}

	switch resp.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case spec.DataVersionPhase0:
		resp.Phase0.Signature = sig.ToETH2()
	case spec.DataVersionAltair:
		resp.Altair.Signature = sig.ToETH2()
	case spec.DataVersionBellatrix:
		resp.Bellatrix.Signature = sig.ToETH2()
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (b VersionedSignedBeaconBlock) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case spec.DataVersionPhase0:
		marshaller = b.VersionedSignedBeaconBlock.Phase0
	case spec.DataVersionAltair:
		marshaller = b.VersionedSignedBeaconBlock.Altair
	case spec.DataVersionBellatrix:
		marshaller = b.VersionedSignedBeaconBlock.Bellatrix
	default:
		return nil, errors.New("unknown version")
	}

	block, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	resp, err := json.Marshal(versionedSignedBeaconBlockJSON{
		Version: int(b.Version),
		Block:   block,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (b *VersionedSignedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedSignedBeaconBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := spec.VersionedSignedBeaconBlock{Version: spec.DataVersion(raw.Version)}
	switch resp.Version {
	case spec.DataVersionPhase0:
		block := new(eth2p0.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case spec.DataVersionAltair:
		block := new(altair.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case spec.DataVersionBellatrix:
		block := new(bellatrix.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	default:
		return errors.New("unknown version")
	}

	b.VersionedSignedBeaconBlock = resp

	return nil
}

// versionedSignedBeaconBlockJSON is a custom VersionedSignedBeaconBlock serialiser.
type versionedSignedBeaconBlockJSON struct {
	Version int             `json:"version"`
	Block   json.RawMessage `json:"block"`
}

// NewAttestation is a convenience function that returns a new wrapped attestation.
func NewAttestation(att *eth2p0.Attestation) Attestation {
	return Attestation{Attestation: *att}
}

// NewPartialAttestation is a convenience function that returns a new partially signed attestation.
func NewPartialAttestation(att *eth2p0.Attestation, shareIdx int) ParSignedData2 {
	return ParSignedData2{
		SignedData: NewAttestation(att),
		ShareIdx:   shareIdx,
	}
}

// Attestation is a signed attestation and implements SignedData.
type Attestation struct {
	eth2p0.Attestation
}

func (a Attestation) Signature() Signature {
	return SigFromETH2(a.Attestation.Signature)
}

func (a Attestation) SetSignature(sig Signature) (SignedData, error) {
	var resp Attestation
	if err := cloneSignedData(a, &resp); err != nil {
		return nil, err
	}

	resp.Attestation.Signature = sig.ToETH2()

	return resp, nil
}

func (a Attestation) MarshalJSON() ([]byte, error) {
	return a.Attestation.MarshalJSON()
}

func (a *Attestation) UnmarshalJSON(b []byte) error {
	return a.Attestation.UnmarshalJSON(b)
}

// NewSignedVoluntaryExit is a convenience function that returns a new signed voluntary exit.
func NewSignedVoluntaryExit(exit *eth2p0.SignedVoluntaryExit) SignedVoluntaryExit {
	return SignedVoluntaryExit{SignedVoluntaryExit: *exit}
}

// NewPartialSignedVoluntaryExit is a convenience function that returns a new partially signed voluntary exit.
func NewPartialSignedVoluntaryExit(exit *eth2p0.SignedVoluntaryExit, shareIdx int) ParSignedData2 {
	return ParSignedData2{
		SignedData: NewSignedVoluntaryExit(exit),
		ShareIdx:   shareIdx,
	}
}

type SignedVoluntaryExit struct {
	eth2p0.SignedVoluntaryExit
}

func (e SignedVoluntaryExit) Signature() Signature {
	return SigFromETH2(e.SignedVoluntaryExit.Signature)
}

func (e SignedVoluntaryExit) SetSignature(sig Signature) (SignedData, error) {
	var resp SignedVoluntaryExit
	if err := cloneSignedData(e, &resp); err != nil {
		return nil, err
	}

	resp.SignedVoluntaryExit.Signature = sig.ToETH2()

	return resp, nil
}

func (e SignedVoluntaryExit) MarshalJSON() ([]byte, error) {
	return e.SignedVoluntaryExit.MarshalJSON()
}

func (e *SignedVoluntaryExit) UnmarshalJSON(b []byte) error {
	return e.SignedVoluntaryExit.UnmarshalJSON(b)
}

// cloneSignedData clones the signed data by serialising to-from json
// since eth2 types contains pointers. The result is stored
// in the value pointed to by v.
func cloneSignedData(data SignedData, v any) error {
	bytes, err := data.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal signed data")
	}

	if err := json.Unmarshal(bytes, v); err != nil {
		return errors.Wrap(err, "unmarshal signed data")
	}

	return nil
}
