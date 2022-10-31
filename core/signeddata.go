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
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

var (
	_ SignedData = VersionedSignedBeaconBlock{}
	_ SignedData = Attestation{}
	_ SignedData = Signature{}
	_ SignedData = SignedVoluntaryExit{}
	_ SignedData = VersionedSignedBlindedBeaconBlock{}
	_ SignedData = VersionedSignedValidatorRegistration{}
	_ SignedData = SignedRandao{}
	_ SignedData = BeaconCommitteeSelection{}
	_ SignedData = SignedAggregateAndProof{}
	_ SignedData = SignedSyncMessage{}
	_ SignedData = SignedSyncContributionAndProof{}
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

func (Signature) MessageRoot() ([32]byte, error) {
	return [32]byte{}, errors.New("unsigned data root not supported by signature type")
}

func (s Signature) Clone() (SignedData, error) {
	return s.clone(), nil
}

// clone returns a copy of the Signature.
// It is similar to Clone that returns the SignedData interface.

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

func (b VersionedSignedBeaconBlock) MessageRoot() ([32]byte, error) {
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case spec.DataVersionPhase0:
		return b.Phase0.Message.HashTreeRoot()
	case spec.DataVersionAltair:
		return b.Altair.Message.HashTreeRoot()
	case spec.DataVersionBellatrix:
		return b.Bellatrix.Message.HashTreeRoot()
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBeaconBlock`.
	}
}

func (b VersionedSignedBeaconBlock) Clone() (SignedData, error) {
	return b.clone()
}

// clone returns a copy of the VersionedSignedBeaconBlock.
// It is similar to Clone that returns the SignedData interface.

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

// VersionedSignedBlindedBeaconBlock is a signed versioned blinded beacon block and implements SignedData.
type VersionedSignedBlindedBeaconBlock struct {
	eth2api.VersionedSignedBlindedBeaconBlock // Could subtype instead of embed, but aligning with Attestation that cannot subtype.
}

func (b VersionedSignedBlindedBeaconBlock) MessageRoot() ([32]byte, error) {
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case spec.DataVersionBellatrix:
		return b.Bellatrix.Message.HashTreeRoot()
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBlindedBeaconBlock`.
	}
}

func (b VersionedSignedBlindedBeaconBlock) Clone() (SignedData, error) {
	return b.clone()
}

// clone returns a copy of the VersionedSignedBlindedBeaconBlock.
// It is similar to Clone that returns the SignedData interface.

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

func (a Attestation) MessageRoot() ([32]byte, error) {
	return a.Data.HashTreeRoot()
}

func (a Attestation) Clone() (SignedData, error) {
	return a.clone()
}

// clone returns a copy of the Attestation.
// It is similar to Clone that returns the SignedData interface.

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

func (e SignedVoluntaryExit) MessageRoot() ([32]byte, error) {
	return e.Message.HashTreeRoot()
}

func (e SignedVoluntaryExit) Clone() (SignedData, error) {
	return e.clone()
}

// clone returns a copy of the SignedVoluntaryExit.
// It is similar to Clone that returns the SignedData interface.

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

// versionedRawValidatorRegistrationJSON is a custom VersionedSignedValidator serialiser.
type versionedRawValidatorRegistrationJSON struct {
	Version      int             `json:"version"`
	Registration json.RawMessage `json:"registration"`
}

// NewVersionedSignedValidatorRegistration is a convenience function that returns a new signed validator (builder) registration.
func NewVersionedSignedValidatorRegistration(registration *eth2api.VersionedSignedValidatorRegistration) (VersionedSignedValidatorRegistration, error) {
	switch registration.Version {
	case spec.BuilderVersionV1:
		if registration.V1 == nil {
			return VersionedSignedValidatorRegistration{}, errors.New("no V1 registration")
		}
	default:
		return VersionedSignedValidatorRegistration{}, errors.New("unknown version")
	}

	return VersionedSignedValidatorRegistration{VersionedSignedValidatorRegistration: *registration}, nil
}

// NewPartialVersionedSignedValidatorRegistration is a convenience function that returns a new partially signed validator (builder) registration.
func NewPartialVersionedSignedValidatorRegistration(registration *eth2api.VersionedSignedValidatorRegistration, shareIdx int) (ParSignedData, error) {
	wrap, err := NewVersionedSignedValidatorRegistration(registration)
	if err != nil {
		return ParSignedData{}, err
	}

	return ParSignedData{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedValidatorRegistration is a signed versioned validator (builder) registration and implements SignedData.
type VersionedSignedValidatorRegistration struct {
	eth2api.VersionedSignedValidatorRegistration
}

func (r VersionedSignedValidatorRegistration) MessageRoot() ([32]byte, error) {
	switch r.Version {
	case spec.BuilderVersionV1:
		return r.V1.Message.HashTreeRoot()
	default:
		panic("unknown version")
	}
}

func (r VersionedSignedValidatorRegistration) Clone() (SignedData, error) {
	return r.clone()
}

// clone returns a copy of the VersionedSignedValidatorRegistration.
// It is similar to Clone that returns the SignedData interface.

func (r VersionedSignedValidatorRegistration) clone() (VersionedSignedValidatorRegistration, error) {
	var resp VersionedSignedValidatorRegistration
	err := cloneJSONMarshaler(r, &resp)
	if err != nil {
		return VersionedSignedValidatorRegistration{}, errors.Wrap(err, "clone registration")
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
		return nil, errors.Wrap(err, "marshal registration")
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
			return errors.Wrap(err, "unmarshal V1 registration")
		}
		resp.V1 = registration
	default:
		return errors.New("unknown version")
	}

	r.VersionedSignedValidatorRegistration = resp

	return nil
}

// NewPartialSignedRandao is a convenience function that returns a new partially signed Randao Reveal.
func NewPartialSignedRandao(epoch eth2p0.Epoch, randao eth2p0.BLSSignature, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: SignedRandao{SignedEpoch: eth2util.SignedEpoch{
			Epoch:     epoch,
			Signature: randao,
		}},
		ShareIdx: shareIdx,
	}
}

// SignedRandao is a signed Randao Reveal which implements SignedData.
type SignedRandao struct {
	eth2util.SignedEpoch
}

func (s SignedRandao) MessageRoot() ([32]byte, error) {
	return s.SignedEpoch.HashTreeRoot()
}

func (s SignedRandao) Signature() Signature {
	return SigFromETH2(s.SignedEpoch.Signature)
}

func (s SignedRandao) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SignedEpoch.Signature = sig.ToETH2()

	return resp, nil
}

func (s SignedRandao) Clone() (SignedData, error) {
	return s.clone()
}

func (s SignedRandao) MarshalJSON() ([]byte, error) {
	return s.SignedEpoch.MarshalJSON()
}

func (s *SignedRandao) UnmarshalJSON(input []byte) error {
	return s.SignedEpoch.UnmarshalJSON(input)
}

func (s SignedRandao) clone() (SignedRandao, error) {
	var resp SignedRandao
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SignedRandao{}, errors.Wrap(err, "clone randao")
	}

	return resp, nil
}

// NewBeaconCommitteeSelection is a convenience function which returns new signed BeaconCommitteeSelection.
func NewBeaconCommitteeSelection(selection *eth2exp.BeaconCommitteeSelection) BeaconCommitteeSelection {
	return BeaconCommitteeSelection{
		BeaconCommitteeSelection: *selection,
	}
}

// NewPartialSignedBeaconCommitteeSelection is a convenience function which returns new partially signed BeaconCommitteeSelection.
func NewPartialSignedBeaconCommitteeSelection(selection *eth2exp.BeaconCommitteeSelection, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewBeaconCommitteeSelection(selection),
		ShareIdx:   shareIdx,
	}
}

// BeaconCommitteeSelection wraps a BeaconCommitteeSelection which implements SignedData.
type BeaconCommitteeSelection struct {
	eth2exp.BeaconCommitteeSelection
}

func (s BeaconCommitteeSelection) MessageRoot() ([32]byte, error) {
	return eth2util.SlotHashRoot(s.Slot)
}

func (s BeaconCommitteeSelection) Signature() Signature {
	return SigFromETH2(s.SelectionProof)
}

func (s BeaconCommitteeSelection) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SelectionProof = sig.ToETH2()

	return resp, nil
}

func (s BeaconCommitteeSelection) Clone() (SignedData, error) {
	return s.clone()
}

func (s BeaconCommitteeSelection) clone() (BeaconCommitteeSelection, error) {
	var resp BeaconCommitteeSelection
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return BeaconCommitteeSelection{}, errors.Wrap(err, "clone BeaconCommitteeSubscription")
	}

	return resp, nil
}

func (s BeaconCommitteeSelection) MarshalJSON() ([]byte, error) {
	return s.BeaconCommitteeSelection.MarshalJSON()
}

func (s *BeaconCommitteeSelection) UnmarshalJSON(input []byte) error {
	return s.BeaconCommitteeSelection.UnmarshalJSON(input)
}

// SyncCommitteeSelection wraps an eth2exp.SyncCommitteeSelection and implements SignedData.
type SyncCommitteeSelection struct {
	eth2exp.SyncCommitteeSelection
}

func (s SyncCommitteeSelection) MessageRoot() ([32]byte, error) {
	data := altair.SyncAggregatorSelectionData{
		Slot:              s.Slot,
		SubcommitteeIndex: uint64(s.SubcommitteeIndex),
	}

	return data.HashTreeRoot()
}

func (s SyncCommitteeSelection) Signature() Signature {
	return SigFromETH2(s.SelectionProof)
}

func (s SyncCommitteeSelection) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SelectionProof = sig.ToETH2()

	return resp, nil
}

func (s SyncCommitteeSelection) Clone() (SignedData, error) {
	return s.clone()
}

func (s SyncCommitteeSelection) clone() (SyncCommitteeSelection, error) {
	var resp SyncCommitteeSelection
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SyncCommitteeSelection{}, errors.Wrap(err, "clone SyncCommitteeSubscription")
	}

	return resp, nil
}

func (s SyncCommitteeSelection) MarshalJSON() ([]byte, error) {
	return s.SyncCommitteeSelection.MarshalJSON()
}

func (s *SyncCommitteeSelection) UnmarshalJSON(input []byte) error {
	return s.SyncCommitteeSelection.UnmarshalJSON(input)
}

// NewSyncCommitteeSelection is a convenience function which returns new signed SyncCommitteeSelection.
func NewSyncCommitteeSelection(selection *eth2exp.SyncCommitteeSelection) SyncCommitteeSelection {
	return SyncCommitteeSelection{
		SyncCommitteeSelection: *selection,
	}
}

// NewPartialSignedSyncCommitteeSelection is a convenience function which returns new partially signed SyncCommitteeSelection.
func NewPartialSignedSyncCommitteeSelection(selection *eth2exp.SyncCommitteeSelection, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSyncCommitteeSelection(selection),
		ShareIdx:   shareIdx,
	}
}

// NewSignedAggregateAndProof is a convenience function which returns a new signed SignedAggregateAndProof.
func NewSignedAggregateAndProof(data *eth2p0.SignedAggregateAndProof) SignedAggregateAndProof {
	return SignedAggregateAndProof{SignedAggregateAndProof: *data}
}

// NewPartialSignedAggregateAndProof is a convenience function which returns a new partially signed SignedAggregateAndProof.
func NewPartialSignedAggregateAndProof(data *eth2p0.SignedAggregateAndProof, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSignedAggregateAndProof(data),
		ShareIdx:   shareIdx,
	}
}

// SignedAggregateAndProof wraps eth2p0.SignedAggregateAndProof and implements SignedData.
type SignedAggregateAndProof struct {
	eth2p0.SignedAggregateAndProof
}

func (s SignedAggregateAndProof) MessageRoot() ([32]byte, error) {
	return s.Message.HashTreeRoot()
}

func (s SignedAggregateAndProof) Signature() Signature {
	return SigFromETH2(s.SignedAggregateAndProof.Signature)
}

func (s SignedAggregateAndProof) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SignedAggregateAndProof.Signature = sig.ToETH2()

	return resp, nil
}

func (s SignedAggregateAndProof) Clone() (SignedData, error) {
	return s.clone()
}

func (s SignedAggregateAndProof) clone() (SignedAggregateAndProof, error) {
	var resp SignedAggregateAndProof
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SignedAggregateAndProof{}, errors.Wrap(err, "clone signed aggregate and proof")
	}

	return resp, nil
}

func (s SignedAggregateAndProof) MarshalJSON() ([]byte, error) {
	return s.SignedAggregateAndProof.MarshalJSON()
}

func (s *SignedAggregateAndProof) UnmarshalJSON(input []byte) error {
	return s.SignedAggregateAndProof.UnmarshalJSON(input)
}

// NewSignedSyncMessage is a convenience function which returns new signed SignedSyncMessage.
func NewSignedSyncMessage(data *altair.SyncCommitteeMessage) SignedSyncMessage {
	return SignedSyncMessage{SyncCommitteeMessage: *data}
}

// NewPartialSignedSyncMessage is a convenience function which returns a new partially signed SignedSyncMessage.
func NewPartialSignedSyncMessage(data *altair.SyncCommitteeMessage, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSignedSyncMessage(data),
		ShareIdx:   shareIdx,
	}
}

// SignedSyncMessage wraps altair.SyncCommitteeMessage and implements SignedData.
type SignedSyncMessage struct {
	altair.SyncCommitteeMessage
}

func (s SignedSyncMessage) MessageRoot() ([32]byte, error) {
	return s.BeaconBlockRoot, nil
}

func (s SignedSyncMessage) Signature() Signature {
	return SigFromETH2(s.SyncCommitteeMessage.Signature)
}

func (s SignedSyncMessage) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SyncCommitteeMessage.Signature = sig.ToETH2()

	return resp, nil
}

func (s SignedSyncMessage) Clone() (SignedData, error) {
	return s.clone()
}

func (s SignedSyncMessage) clone() (SignedSyncMessage, error) {
	var resp SignedSyncMessage
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SignedSyncMessage{}, errors.Wrap(err, "clone signed sync message")
	}

	return resp, nil
}

func (s SignedSyncMessage) MarshalJSON() ([]byte, error) {
	return s.SyncCommitteeMessage.MarshalJSON()
}

func (s *SignedSyncMessage) UnmarshalJSON(input []byte) error {
	return s.SyncCommitteeMessage.UnmarshalJSON(input)
}

func NewSignedSyncContributionAndProof(proof *altair.SignedContributionAndProof) SignedSyncContributionAndProof {
	return SignedSyncContributionAndProof{SignedContributionAndProof: *proof}
}

func NewPartialSignedSyncContributionAndProof(proof *altair.SignedContributionAndProof, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSignedSyncContributionAndProof(proof),
		ShareIdx:   shareIdx,
	}
}

// SignedSyncContributionAndProof wraps altair.SignedContributionAndProof and implements SignedData.
type SignedSyncContributionAndProof struct {
	altair.SignedContributionAndProof
}

func (s SignedSyncContributionAndProof) MessageRoot() ([32]byte, error) {
	return s.Message.HashTreeRoot()
}

func (s SignedSyncContributionAndProof) Signature() Signature {
	return SigFromETH2(s.SignedContributionAndProof.Signature)
}

func (s SignedSyncContributionAndProof) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SignedContributionAndProof.Signature = sig.ToETH2()

	return resp, err
}

func (s SignedSyncContributionAndProof) Clone() (SignedData, error) {
	return s.clone()
}

func (s SignedSyncContributionAndProof) clone() (SignedSyncContributionAndProof, error) {
	var resp SignedSyncContributionAndProof
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SignedSyncContributionAndProof{}, errors.Wrap(err, "clone signed sync contribution")
	}

	return resp, nil
}

func (s SignedSyncContributionAndProof) MarshalJSON() ([]byte, error) {
	return s.SignedContributionAndProof.MarshalJSON()
}

func (s *SignedSyncContributionAndProof) UnmarshalJSON(input []byte) error {
	return s.SignedContributionAndProof.UnmarshalJSON(input)
}

// cloneJSONMarshaler clones the marshaler by serialising to-from json
// since eth2 types contain pointers. The result is stored in the value pointed to by v.
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
