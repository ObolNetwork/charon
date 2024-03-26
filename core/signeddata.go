// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"encoding/json"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
)

var (
	_ SignedData = VersionedSignedProposal{}
	_ SignedData = Attestation{}
	_ SignedData = Signature{}
	_ SignedData = SignedVoluntaryExit{}
	_ SignedData = VersionedSignedBlindedProposal{}
	_ SignedData = VersionedSignedValidatorRegistration{}
	_ SignedData = SignedRandao{}
	_ SignedData = BeaconCommitteeSelection{}
	_ SignedData = SignedAggregateAndProof{}
	_ SignedData = SignedSyncMessage{}
	_ SignedData = SyncContributionAndProof{}
	_ SignedData = SignedSyncContributionAndProof{}
	_ SignedData = SyncCommitteeSelection{}

	// Some types support SSZ marshalling and unmarshalling.
	_ ssz.Marshaler   = VersionedSignedProposal{}
	_ ssz.Marshaler   = Attestation{}
	_ ssz.Marshaler   = VersionedSignedBlindedProposal{}
	_ ssz.Marshaler   = SignedAggregateAndProof{}
	_ ssz.Marshaler   = SignedSyncMessage{}
	_ ssz.Marshaler   = SyncContributionAndProof{}
	_ ssz.Marshaler   = SignedSyncContributionAndProof{}
	_ ssz.Unmarshaler = new(VersionedSignedProposal)
	_ ssz.Unmarshaler = new(Attestation)
	_ ssz.Unmarshaler = new(VersionedSignedBlindedProposal)
	_ ssz.Unmarshaler = new(SignedAggregateAndProof)
	_ ssz.Unmarshaler = new(SignedSyncMessage)
	_ ssz.Unmarshaler = new(SyncContributionAndProof)
	_ ssz.Unmarshaler = new(SignedSyncContributionAndProof)
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
	return [32]byte{}, errors.New("signed message root not supported by signature type")
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

// NewVersionedSignedProposal validates and returns a new VersionedSignedProposal.
func NewVersionedSignedProposal(proposal *eth2api.VersionedSignedProposal) (VersionedSignedProposal, error) {
	switch proposal.Version {
	case eth2spec.DataVersionPhase0:
		if proposal.Phase0 == nil {
			return VersionedSignedProposal{}, errors.New("no phase0 proposal")
		}
	case eth2spec.DataVersionAltair:
		if proposal.Altair == nil {
			return VersionedSignedProposal{}, errors.New("no altair proposal")
		}
	case eth2spec.DataVersionBellatrix:
		if proposal.Bellatrix == nil && !proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no bellatrix proposal")
		}
		if proposal.BellatrixBlinded == nil && proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no bellatrix blinded proposal")
		}
	case eth2spec.DataVersionCapella:
		if proposal.Capella == nil && !proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no capella proposal")
		}
		if proposal.CapellaBlinded == nil && proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no capella blinded proposal")
		}
	case eth2spec.DataVersionDeneb:
		if proposal.Deneb == nil && !proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no deneb proposal")
		}
		if proposal.DenebBlinded == nil && proposal.Blinded {
			return VersionedSignedProposal{}, errors.New("no deneb blinded proposal")
		}
	default:
		return VersionedSignedProposal{}, errors.New("unknown version")
	}

	return VersionedSignedProposal{VersionedSignedProposal: *proposal}, nil
}

// NewPartialVersionedSignedProposal validates and returns a new partial VersionedSignedProposal.
func NewPartialVersionedSignedProposal(proposal *eth2api.VersionedSignedProposal, shareIdx int) (ParSignedData, error) {
	wrap, err := NewVersionedSignedProposal(proposal)
	if err != nil {
		return ParSignedData{}, err
	}

	return ParSignedData{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedProposal is a signed versioned proposal and implements SignedData.
type VersionedSignedProposal struct {
	eth2api.VersionedSignedProposal
}

func (p VersionedSignedProposal) Signature() Signature {
	switch p.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case eth2spec.DataVersionPhase0:
		return SigFromETH2(p.Phase0.Signature)
	case eth2spec.DataVersionAltair:
		return SigFromETH2(p.Altair.Signature)
	case eth2spec.DataVersionBellatrix:
		if p.Blinded {
			return SigFromETH2(p.BellatrixBlinded.Signature)
		} else {
			return SigFromETH2(p.Bellatrix.Signature)
		}
	case eth2spec.DataVersionCapella:
		if p.Blinded {
			return SigFromETH2(p.CapellaBlinded.Signature)
		} else {
			return SigFromETH2(p.Capella.Signature)
		}
	case eth2spec.DataVersionDeneb:
		if p.Blinded {
			return SigFromETH2(p.DenebBlinded.Signature)
		} else {
			return SigFromETH2(p.Deneb.SignedBlock.Signature)
		}
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedProposal`.
	}
}

func (p VersionedSignedProposal) SetSignature(sig Signature) (SignedData, error) {
	resp, err := p.clone()
	if err != nil {
		return nil, err
	}

	switch resp.Version {
	// No block nil checks since `NewVersionedSignedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		resp.Phase0.Signature = sig.ToETH2()
	case eth2spec.DataVersionAltair:
		resp.Altair.Signature = sig.ToETH2()
	case eth2spec.DataVersionBellatrix:
		if resp.Blinded {
			resp.BellatrixBlinded.Signature = sig.ToETH2()
		} else {
			resp.Bellatrix.Signature = sig.ToETH2()
		}
	case eth2spec.DataVersionCapella:
		if resp.Blinded {
			resp.CapellaBlinded.Signature = sig.ToETH2()
		} else {
			resp.Capella.Signature = sig.ToETH2()
		}
	case eth2spec.DataVersionDeneb:
		if resp.Blinded {
			resp.DenebBlinded.Signature = sig.ToETH2()
		} else {
			resp.Deneb.SignedBlock.Signature = sig.ToETH2()
		}
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (p VersionedSignedProposal) MessageRoot() ([32]byte, error) {
	switch p.Version {
	// No block nil checks since `NewVersionedSignedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		return p.Phase0.Message.HashTreeRoot()
	case eth2spec.DataVersionAltair:
		return p.Altair.Message.HashTreeRoot()
	case eth2spec.DataVersionBellatrix:
		if p.Blinded {
			return p.BellatrixBlinded.Message.HashTreeRoot()
		} else {
			return p.Bellatrix.Message.HashTreeRoot()
		}
	case eth2spec.DataVersionCapella:
		if p.Blinded {
			return p.CapellaBlinded.Message.HashTreeRoot()
		} else {
			return p.Capella.Message.HashTreeRoot()
		}
	case eth2spec.DataVersionDeneb:
		if p.Blinded {
			return p.DenebBlinded.Message.HashTreeRoot()
		} else {
			return p.Deneb.SignedBlock.Message.HashTreeRoot()
		}
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedProposal`.
	}
}

func (p VersionedSignedProposal) Clone() (SignedData, error) {
	return p.clone()
}

// clone returns a copy of the VersionedSignedProposal.
// It is similar to Clone that returns the SignedData interface.
func (p VersionedSignedProposal) clone() (VersionedSignedProposal, error) {
	var resp VersionedSignedProposal
	err := cloneJSONMarshaler(p, &resp)
	if err != nil {
		return VersionedSignedProposal{}, errors.Wrap(err, "clone proposal")
	}

	return resp, nil
}

func (p VersionedSignedProposal) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch p.Version {
	// No proposal nil checks since `NewVersionedSignedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		marshaller = p.VersionedSignedProposal.Phase0
	case eth2spec.DataVersionAltair:
		marshaller = p.VersionedSignedProposal.Altair
	case eth2spec.DataVersionBellatrix:
		if p.Blinded {
			marshaller = p.VersionedSignedProposal.BellatrixBlinded
		} else {
			marshaller = p.VersionedSignedProposal.Bellatrix
		}
	case eth2spec.DataVersionCapella:
		if p.Blinded {
			marshaller = p.VersionedSignedProposal.CapellaBlinded
		} else {
			marshaller = p.VersionedSignedProposal.Capella
		}
	case eth2spec.DataVersionDeneb:
		if p.Blinded {
			marshaller = p.VersionedSignedProposal.DenebBlinded
		} else {
			marshaller = p.VersionedSignedProposal.Deneb
		}
	default:
		return nil, errors.New("unknown version")
	}

	proposal, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposal")
	}

	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		return nil, errors.Wrap(err, "convert version")
	}

	resp, err := json.Marshal(versionedRawBlockJSON{
		Version: version,
		Block:   proposal,
		Blinded: p.Blinded,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (p *VersionedSignedProposal) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := eth2api.VersionedSignedProposal{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.DataVersionPhase0:
		block := new(eth2p0.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case eth2spec.DataVersionAltair:
		block := new(altair.SignedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case eth2spec.DataVersionBellatrix:
		if raw.Blinded {
			block := new(eth2bellatrix.SignedBlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal bellatrix blinded")
			}
			resp.BellatrixBlinded = block
		} else {
			block := new(bellatrix.SignedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal bellatrix")
			}
			resp.Bellatrix = block
		}
	case eth2spec.DataVersionCapella:
		if raw.Blinded {
			block := new(eth2capella.SignedBlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal capella blinded")
			}
			resp.CapellaBlinded = block
		} else {
			block := new(capella.SignedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal capella")
			}
			resp.Capella = block
		}
	case eth2spec.DataVersionDeneb:
		if raw.Blinded {
			block := new(eth2deneb.SignedBlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal deneb blinded")
			}
			resp.DenebBlinded = block
		} else {
			block := new(eth2deneb.SignedBlockContents)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal deneb")
			}
			resp.Deneb = block
		}
	default:
		return errors.New("unknown version")
	}

	p.VersionedSignedProposal = resp

	return nil
}

// NewVersionedSignedBlindedProposal validates and returns a new wrapped VersionedSignedBlindedProposal.
func NewVersionedSignedBlindedProposal(block *eth2api.VersionedSignedBlindedProposal) (VersionedSignedBlindedProposal, error) {
	switch block.Version {
	case eth2spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedSignedBlindedProposal{}, errors.New("no bellatrix block")
		}
	case eth2spec.DataVersionCapella:
		if block.Capella == nil {
			return VersionedSignedBlindedProposal{}, errors.New("no capella block")
		}
	case eth2spec.DataVersionDeneb:
		if block.Deneb == nil {
			return VersionedSignedBlindedProposal{}, errors.New("no deneb block")
		}
	default:
		return VersionedSignedBlindedProposal{}, errors.New("unknown version")
	}

	return VersionedSignedBlindedProposal{VersionedSignedBlindedProposal: *block}, nil
}

// NewPartialVersionedSignedBlindedProposal is a convenience function that returns a new partial signed proposal.
func NewPartialVersionedSignedBlindedProposal(proposal *eth2api.VersionedSignedBlindedProposal, shareIdx int) (ParSignedData, error) {
	wrap, err := NewVersionedSignedBlindedProposal(proposal)
	if err != nil {
		return ParSignedData{}, err
	}

	return ParSignedData{
		SignedData: wrap,
		ShareIdx:   shareIdx,
	}, nil
}

// VersionedSignedBlindedProposal is a signed versioned blinded proposal and implements SignedData.
type VersionedSignedBlindedProposal struct {
	eth2api.VersionedSignedBlindedProposal
}

func (p VersionedSignedBlindedProposal) Signature() Signature {
	switch p.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case eth2spec.DataVersionBellatrix:
		return SigFromETH2(p.Bellatrix.Signature)
	case eth2spec.DataVersionCapella:
		return SigFromETH2(p.Capella.Signature)
	case eth2spec.DataVersionDeneb:
		return SigFromETH2(p.Deneb.Signature)
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBlindedProposal`.
	}
}

func (p VersionedSignedBlindedProposal) SetSignature(sig Signature) (SignedData, error) {
	resp, err := p.clone()
	if err != nil {
		return nil, err
	}

	switch resp.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case eth2spec.DataVersionBellatrix:
		resp.Bellatrix.Signature = sig.ToETH2()
	case eth2spec.DataVersionCapella:
		resp.Capella.Signature = sig.ToETH2()
	case eth2spec.DataVersionDeneb:
		resp.Deneb.Signature = sig.ToETH2()
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (p VersionedSignedBlindedProposal) MessageRoot() ([32]byte, error) {
	switch p.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case eth2spec.DataVersionBellatrix:
		return p.Bellatrix.Message.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		return p.Capella.Message.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		return p.Deneb.Message.HashTreeRoot()
	default:
		panic("unknown version") // Note this is avoided by using `NewVersionedSignedBlindedProposal`.
	}
}

func (p VersionedSignedBlindedProposal) Clone() (SignedData, error) {
	return p.clone()
}

// clone returns a copy of the VersionedSignedBlindedProposal.
// It is similar to Clone that returns the SignedData interface.
func (p VersionedSignedBlindedProposal) clone() (VersionedSignedBlindedProposal, error) {
	var resp VersionedSignedBlindedProposal
	err := cloneJSONMarshaler(p, &resp)
	if err != nil {
		return VersionedSignedBlindedProposal{}, errors.Wrap(err, "clone blinded proposal")
	}

	return resp, nil
}

func (p VersionedSignedBlindedProposal) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch p.Version {
	// No block nil checks since `NewVersionedSignedBlindedProposal` assumed.
	case eth2spec.DataVersionBellatrix:
		marshaller = p.VersionedSignedBlindedProposal.Bellatrix
	case eth2spec.DataVersionCapella:
		marshaller = p.VersionedSignedBlindedProposal.Capella
	case eth2spec.DataVersionDeneb:
		marshaller = p.VersionedSignedBlindedProposal.Deneb
	default:
		return nil, errors.New("unknown version")
	}

	block, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal block")
	}

	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		return nil, errors.Wrap(err, "convert version")
	}

	resp, err := json.Marshal(versionedRawBlockJSON{
		Version: version,
		Block:   block,
		Blinded: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (p *VersionedSignedBlindedProposal) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}
	if !raw.Blinded {
		return errors.New("unmarshalled block is not blinded")
	}

	resp := eth2api.VersionedSignedBlindedProposal{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.DataVersionBellatrix:
		block := new(eth2bellatrix.SignedBlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	case eth2spec.DataVersionCapella:
		block := new(eth2capella.SignedBlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal capella")
		}
		resp.Capella = block
	case eth2spec.DataVersionDeneb:
		block := new(eth2deneb.SignedBlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal deneb")
		}
		resp.Deneb = block
	default:
		return errors.New("unknown version")
	}

	p.VersionedSignedBlindedProposal = resp

	return nil
}

// versionedRawBlockJSON is a custom VersionedSignedBeaconBlock or VersionedSignedBlindedBeaconBlock serialiser.
type versionedRawBlockJSON struct {
	Version eth2util.DataVersion `json:"version"`
	Block   json.RawMessage      `json:"block"`
	Blinded bool                 `json:"blinded,omitempty"`
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

func (a Attestation) MarshalSSZ() ([]byte, error) {
	return a.Attestation.MarshalSSZ()
}

func (a Attestation) MarshalSSZTo(dst []byte) ([]byte, error) {
	return a.Attestation.MarshalSSZTo(dst)
}

func (a Attestation) SizeSSZ() int {
	return a.Attestation.SizeSSZ()
}

func (a *Attestation) UnmarshalSSZ(b []byte) error {
	return a.Attestation.UnmarshalSSZ(b)
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
	Version      eth2util.BuilderVersion `json:"version"`
	Registration json.RawMessage         `json:"registration"`
}

// NewVersionedSignedValidatorRegistration is a convenience function that returns a new signed validator (builder) registration.
func NewVersionedSignedValidatorRegistration(registration *eth2api.VersionedSignedValidatorRegistration) (VersionedSignedValidatorRegistration, error) {
	switch registration.Version {
	case eth2spec.BuilderVersionV1:
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
	case eth2spec.BuilderVersionV1:
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
	case eth2spec.BuilderVersionV1:
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
	case eth2spec.BuilderVersionV1:
		resp.V1.Signature = sig.ToETH2()
	default:
		return nil, errors.New("unknown type")
	}

	return resp, nil
}

func (r VersionedSignedValidatorRegistration) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch r.Version {
	case eth2spec.BuilderVersionV1:
		marshaller = r.VersionedSignedValidatorRegistration.V1
	default:
		return nil, errors.New("unknown version")
	}

	registration, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal registration")
	}

	version, err := eth2util.BuilderVersionFromETH2(r.Version)
	if err != nil {
		return nil, errors.Wrap(err, "convert version")
	}

	resp, err := json.Marshal(versionedRawValidatorRegistrationJSON{
		Version:      version,
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

	resp := eth2api.VersionedSignedValidatorRegistration{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.BuilderVersionV1:
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

// NewSignedRandao is a convenience function that returns a new signed Randao Reveal.
func NewSignedRandao(epoch eth2p0.Epoch, randao eth2p0.BLSSignature) SignedRandao {
	return SignedRandao{
		SignedEpoch: eth2util.SignedEpoch{
			Epoch:     epoch,
			Signature: randao,
		},
	}
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

// SyncCommitteeSelection wraps an eth2exp.SyncCommitteeSelection and implements SignedData.
type SyncCommitteeSelection struct {
	eth2exp.SyncCommitteeSelection
}

// MessageRoots returns the signing roots for the provided SyncCommitteeSelection.
// Refer https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#syncaggregatorselectiondata
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

func (s SignedAggregateAndProof) MarshalSSZ() ([]byte, error) {
	return s.SignedAggregateAndProof.MarshalSSZ()
}

func (s SignedAggregateAndProof) MarshalSSZTo(dst []byte) ([]byte, error) {
	return s.SignedAggregateAndProof.MarshalSSZTo(dst)
}

func (s SignedAggregateAndProof) SizeSSZ() int {
	return s.SignedAggregateAndProof.SizeSSZ()
}

func (s *SignedAggregateAndProof) UnmarshalSSZ(b []byte) error {
	return s.SignedAggregateAndProof.UnmarshalSSZ(b)
}

// SyncCommitteeMessage: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#synccommitteemessage.

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

func (s SignedSyncMessage) MarshalSSZ() ([]byte, error) {
	return s.SyncCommitteeMessage.MarshalSSZ()
}

func (s SignedSyncMessage) MarshalSSZTo(dst []byte) ([]byte, error) {
	return s.SyncCommitteeMessage.MarshalSSZTo(dst)
}

func (s SignedSyncMessage) SizeSSZ() int {
	return s.SyncCommitteeMessage.SizeSSZ()
}

func (s *SignedSyncMessage) UnmarshalSSZ(b []byte) error {
	return s.SyncCommitteeMessage.UnmarshalSSZ(b)
}

// ContributionAndProof: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#contributionandproof.

// NewSyncContributionAndProof is a convenience function that returns a new signed altair.ContributionAndProof.
func NewSyncContributionAndProof(proof *altair.ContributionAndProof) SyncContributionAndProof {
	return SyncContributionAndProof{ContributionAndProof: *proof}
}

// NewPartialSyncContributionAndProof is a convenience function that returns a new partially signed altair.ContributionAndProof.
func NewPartialSyncContributionAndProof(proof *altair.ContributionAndProof, shareIdx int) ParSignedData {
	return ParSignedData{
		SignedData: NewSyncContributionAndProof(proof),
		ShareIdx:   shareIdx,
	}
}

// SyncContributionAndProof wraps altair.ContributionAndProof and implements SignedData.
type SyncContributionAndProof struct {
	altair.ContributionAndProof
}

// MessageRoots returns the signing roots for the provided SyncContributionAndProof.
// Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#aggregation-selection.
func (s SyncContributionAndProof) MessageRoot() ([32]byte, error) {
	data := altair.SyncAggregatorSelectionData{
		Slot:              s.ContributionAndProof.Contribution.Slot,
		SubcommitteeIndex: s.ContributionAndProof.Contribution.SubcommitteeIndex,
	}

	return data.HashTreeRoot()
}

func (s SyncContributionAndProof) Signature() Signature {
	return SigFromETH2(s.ContributionAndProof.SelectionProof)
}

func (s SyncContributionAndProof) SetSignature(sig Signature) (SignedData, error) {
	resp, err := s.clone()
	if err != nil {
		return nil, err
	}

	resp.SelectionProof = sig.ToETH2()

	return resp, nil
}

func (s SyncContributionAndProof) Clone() (SignedData, error) {
	return s.clone()
}

func (s SyncContributionAndProof) clone() (SyncContributionAndProof, error) {
	var resp SyncContributionAndProof
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return SyncContributionAndProof{}, errors.Wrap(err, "clone sync contribution and proof")
	}

	return resp, nil
}

func (s SyncContributionAndProof) MarshalJSON() ([]byte, error) {
	return s.ContributionAndProof.MarshalJSON()
}

func (s *SyncContributionAndProof) UnmarshalJSON(input []byte) error {
	return s.ContributionAndProof.UnmarshalJSON(input)
}

func (SyncContributionAndProof) DomainName() signing.DomainName {
	return signing.DomainSyncCommitteeSelectionProof
}

func (s SyncContributionAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Contribution.Slot)
}

func (s SyncContributionAndProof) MarshalSSZ() ([]byte, error) {
	return s.ContributionAndProof.MarshalSSZ()
}

func (s SyncContributionAndProof) MarshalSSZTo(dst []byte) ([]byte, error) {
	return s.ContributionAndProof.MarshalSSZTo(dst)
}

func (s SyncContributionAndProof) SizeSSZ() int {
	return s.ContributionAndProof.SizeSSZ()
}

func (s *SyncContributionAndProof) UnmarshalSSZ(b []byte) error {
	return s.ContributionAndProof.UnmarshalSSZ(b)
}

// SignedContributionAndProof: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#signedcontributionandproof.

// NewSignedSyncContributionAndProof is a convenience function that returns a new signed altair.SignedContributionAndProof.
func NewSignedSyncContributionAndProof(proof *altair.SignedContributionAndProof) SignedSyncContributionAndProof {
	return SignedSyncContributionAndProof{SignedContributionAndProof: *proof}
}

// NewPartialSignedSyncContributionAndProof is a convenience function that returns a new partially signed altair.SignedContributionAndProof.
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

// MessageRoots returns the signing roots for the provided SignedSyncContributionAndProof.
// Refer get_contribution_and_proof_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution.
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

func (s SignedSyncContributionAndProof) MarshalSSZ() ([]byte, error) {
	return s.SignedContributionAndProof.MarshalSSZ()
}

func (s SignedSyncContributionAndProof) MarshalSSZTo(dst []byte) ([]byte, error) {
	return s.SignedContributionAndProof.MarshalSSZTo(dst)
}

func (s SignedSyncContributionAndProof) SizeSSZ() int {
	return s.SignedContributionAndProof.SizeSSZ()
}

func (s *SignedSyncContributionAndProof) UnmarshalSSZ(b []byte) error {
	return s.SignedContributionAndProof.UnmarshalSSZ(b)
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
