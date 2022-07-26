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

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
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
	_ SignedData = VersionedSignedBlindedBeaconBlock{}
	_ SignedData = VersionedSignedValidatorRegistration{} // name in the builder spec SignedValidatorRegistrationV1 or SignedBuilderRegistration
)

// SigFromETH2 returns a new signature from eth2 phase0 BLSSignature.
func SigFromETH2(sig eth2p0.BLSSignature) Signature {
	s := make(Signature, sigLen)
	copy(s, sig[:])

	return s
}

// NewPartialSignature is a convenience function that returns a new partially signature.
func NewPartialSignature(sig Signature, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: sig,
		ShareIdx:   shareIdx,
	}
}

// Signature is a BLS12-381 Signature. It implements SignedData.
type Signature []byte

func (s Signature) Clone() (SignedData, error) {
	return s.clone(), nil
}

// clone returns a copy of the Signature.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (s Signature) clone() Signature {
	resp := make([]byte, len(s))
	copy(resp, s)

	return resp
}

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
func NewPartialVersionedSignedBeaconBlock(block *spec.VersionedSignedBeaconBlock, shareIdx int) (ParSignedData, error) {
	wrap, err := NewVersionedSignedBeaconBlock(block)
	if err != nil {
		return ParSignedData{}, err
	}

	return ParSignedData{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedBeaconBlock is a signed versioned beacon block and implements SignedData.
type VersionedSignedBeaconBlock struct {
	spec.VersionedSignedBeaconBlock // Could subtype instead of embed, but aligning with Attestation that cannot subtype.
}

func (b VersionedSignedBeaconBlock) Clone() (SignedData, error) {
	return b.clone()
}

// clone returns a copy of the VersionedSignedBeaconBlock.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (b VersionedSignedBeaconBlock) clone() (VersionedSignedBeaconBlock, error) {
	var resp VersionedSignedBeaconBlock
	err := cloneJSONMarshaler(b, &resp)
	if err != nil {
		return VersionedSignedBeaconBlock{}, errors.Wrap(err, "clone block")
	}

	return resp, nil
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
	resp, err := b.clone()
	if err != nil {
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

	resp, err := json.Marshal(versionedRawBlockJSON{
		Version: int(b.Version),
		Block:   block,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (b *VersionedSignedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
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

// VersionedSignedBlindedBeaconBlock is a signed versioned blinded beacon block and implements SignedData.
type VersionedSignedBlindedBeaconBlock struct {
	eth2api.VersionedSignedBlindedBeaconBlock // Could subtype instead of embed, but aligning with Attestation that cannot subtype.
}

// NewVersionedSignedBlindedBeaconBlock validates and returns a new wrapped VersionedSignedBlindedBeaconBlock.
func NewVersionedSignedBlindedBeaconBlock(block *eth2api.VersionedSignedBlindedBeaconBlock) (VersionedSignedBlindedBeaconBlock, error) {
	switch block.Version {
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedSignedBlindedBeaconBlock{}, errors.New("no bellatrix block")
		}
	default:
		return VersionedSignedBlindedBeaconBlock{}, errors.New("unknown version")
	}

	return VersionedSignedBlindedBeaconBlock{VersionedSignedBlindedBeaconBlock: *block}, nil
}

// NewPartialVersionedSignedBlindedBeaconBlock is a convenience function that returns a new partial signed block.
func NewPartialVersionedSignedBlindedBeaconBlock(block *eth2api.VersionedSignedBlindedBeaconBlock, shareIdx int) (ParSignedData, error) {
	wrap, err := NewVersionedSignedBlindedBeaconBlock(block)
	if err != nil {
		return ParSignedData{}, err
	}

	return ParSignedData{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

func (b VersionedSignedBlindedBeaconBlock) Clone() (SignedData, error) {
	return b.clone()
}

// clone returns a copy of the VersionedSignedBlindedBeaconBlock.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (b VersionedSignedBlindedBeaconBlock) clone() (VersionedSignedBlindedBeaconBlock, error) {
	var resp VersionedSignedBlindedBeaconBlock
	err := cloneJSONMarshaler(b, &resp)
	if err != nil {
		return VersionedSignedBlindedBeaconBlock{}, errors.Wrap(err, "clone block")
	}

	return resp, nil
}

func (b VersionedSignedBlindedBeaconBlock) Signature() Signature {
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case spec.DataVersionBellatrix:
		return SigFromETH2(b.Bellatrix.Signature)
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBlindedBeaconBlock`.
	}
}

func (b VersionedSignedBlindedBeaconBlock) SetSignature(sig Signature) (SignedData, error) {
	resp, err := b.clone()
	if err != nil {
		return nil, err
	}

	switch resp.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case spec.DataVersionBellatrix:
		resp.Bellatrix.Signature = sig.ToETH2()
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (b VersionedSignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case spec.DataVersionBellatrix:
		marshaller = b.VersionedSignedBlindedBeaconBlock.Bellatrix
	default:
		return nil, errors.New("unknown version")
	}

	block, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	resp, err := json.Marshal(versionedRawBlockJSON{
		Version: int(b.Version),
		Block:   block,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (b *VersionedSignedBlindedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := eth2api.VersionedSignedBlindedBeaconBlock{Version: spec.DataVersion(raw.Version)}
	switch resp.Version {
	case spec.DataVersionBellatrix:
		block := new(eth2v1.SignedBlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	default:
		return errors.New("unknown version")
	}

	b.VersionedSignedBlindedBeaconBlock = resp

	return nil
}

// versionedRawBlockJSON is a custom VersionedSignedBeaconBlock or VersionedSignedBlindedBeaconBlock serialiser.
type versionedRawBlockJSON struct {
	Version int             `json:"version"`
	Block   json.RawMessage `json:"block"`
}

// NewAttestation is a convenience function that returns a new wrapped attestation.
func NewAttestation(att *eth2p0.Attestation) Attestation {
	return Attestation{Attestation: *att}
}

// NewPartialAttestation is a convenience function that returns a new partially signed attestation.
func NewPartialAttestation(att *eth2p0.Attestation, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewAttestation(att),
		ShareIdx:   shareIdx,
	}
}

// Attestation is a signed attestation and implements SignedData.
type Attestation struct {
	eth2p0.Attestation
}

func (a Attestation) Clone() (SignedData, error) {
	return a.clone()
}

// clone returns a copy of the Attestation.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (a Attestation) clone() (Attestation, error) {
	var resp Attestation
	err := cloneJSONMarshaler(a, &resp)
	if err != nil {
		return Attestation{}, errors.Wrap(err, "clone attestation")
	}

	return resp, nil
}

func (a Attestation) Signature() Signature {
	return SigFromETH2(a.Attestation.Signature)
}

func (a Attestation) SetSignature(sig Signature) (SignedData, error) {
	resp, err := a.clone()
	if err != nil {
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
func NewPartialSignedVoluntaryExit(exit *eth2p0.SignedVoluntaryExit, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSignedVoluntaryExit(exit),
		ShareIdx:   shareIdx,
	}
}

type SignedVoluntaryExit struct {
	eth2p0.SignedVoluntaryExit
}

func (e SignedVoluntaryExit) Clone() (SignedData, error) {
	return e.clone()
}

// clone returns a copy of the SignedVoluntaryExit.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (e SignedVoluntaryExit) clone() (SignedVoluntaryExit, error) {
	var resp SignedVoluntaryExit
	err := cloneJSONMarshaler(e, &resp)
	if err != nil {
		return SignedVoluntaryExit{}, errors.Wrap(err, "clone exit")
	}

	return resp, nil
}

func (e SignedVoluntaryExit) Signature() Signature {
	return SigFromETH2(e.SignedVoluntaryExit.Signature)
}

func (e SignedVoluntaryExit) SetSignature(sig Signature) (SignedData, error) {
	resp, err := e.clone()
	if err != nil {
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

// VersionedSignedValidatorRegistration is a signed versioned validator (builder) registration and implements SignedData.
type VersionedSignedValidatorRegistration struct {
	eth2api.VersionedSignedValidatorRegistration
}

// versionedRawValidatorRegistrationJSON is a custom VersionedSignedValidator serialiser.
type versionedRawValidatorRegistrationJSON struct {
	Version      int             `json:"version"`
	Registration json.RawMessage `json:"registration"`
}

func (r VersionedSignedValidatorRegistration) Clone() (SignedData, error) {
	return r.clone()
}

// clone returns a copy of the VersionedSignedValidatorRegistration.
// It is similar to Clone that returns the SignedData interface.
//nolint:revive // similar method names.
func (r VersionedSignedValidatorRegistration) clone() (VersionedSignedValidatorRegistration, error) {
	var resp VersionedSignedValidatorRegistration
	err := cloneJSONMarshaler(r, &resp)
	if err != nil {
		return VersionedSignedValidatorRegistration{}, errors.Wrap(err, "clone block")
	}

	return resp, nil
}

func (r VersionedSignedValidatorRegistration) Signature() Signature {
	switch r.Version {
	case spec.BuilderVersionV1:
		return SigFromETH2(r.V1.Signature)
	default:
		panic("unknown version")
	}
}

func (r VersionedSignedValidatorRegistration) SetSignature(sig Signature) (SignedData, error) {
	resp, err := r.clone()
	if err != nil {
		return nil, err
	}

	switch resp.Version {
	case spec.BuilderVersionV1:
		resp.V1.Signature = sig.ToETH2()
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (r VersionedSignedValidatorRegistration) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch r.Version {
	case spec.BuilderVersionV1:
		marshaller = r.VersionedSignedValidatorRegistration.V1
	default:
		return nil, errors.New("unknown version")
	}

	registration, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	resp, err := json.Marshal(versionedRawValidatorRegistrationJSON{
		Version:      int(r.Version),
		Registration: registration,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (r *VersionedSignedValidatorRegistration) UnmarshalJSON(input []byte) error {
	var raw versionedRawValidatorRegistrationJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal validator (builder) registration")
	}

	resp := eth2api.VersionedSignedValidatorRegistration{Version: spec.BuilderVersion(raw.Version)}
	switch resp.Version {
	case spec.BuilderVersionV1:
		registration := new(eth2v1.SignedValidatorRegistration)
		if err := json.Unmarshal(raw.Registration, &registration); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.V1 = registration
	default:
		return errors.New("unknown version")
	}

	r.VersionedSignedValidatorRegistration = resp

	return nil
}

// cloneJSONMarshaler clones the marshaler by serialising to-from json
// since eth2 types contains pointers. The result is stored
// in the value pointed to by v.
func cloneJSONMarshaler(data json.Marshaler, v any) error {
	bytes, err := data.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal data")
	}

	if err := json.Unmarshal(bytes, v); err != nil {
		return errors.Wrap(err, "unmarshal data")
	}

	return nil
}
