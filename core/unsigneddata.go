// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
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
	"github.com/obolnetwork/charon/eth2util"
)

var (
	_ UnsignedData = AttestationData{}
	_ UnsignedData = AggregatedAttestation{}
	_ UnsignedData = VersionedProposal{}
	_ UnsignedData = VersionedBlindedProposal{}
	_ UnsignedData = VersionedUniversalProposal{}
	_ UnsignedData = SyncContribution{}

	// Some types also support SSZ marshalling and unmarshalling.
	_ ssz.Marshaler   = AttestationData{}
	_ ssz.Marshaler   = AggregatedAttestation{}
	_ ssz.Marshaler   = VersionedProposal{}
	_ ssz.Marshaler   = VersionedBlindedProposal{}
	_ ssz.Marshaler   = SyncContribution{}
	_ ssz.Unmarshaler = new(AttestationData)
	_ ssz.Unmarshaler = new(AggregatedAttestation)
	_ ssz.Unmarshaler = new(VersionedProposal)
	_ ssz.Unmarshaler = new(VersionedBlindedProposal)
	_ ssz.Unmarshaler = new(SyncContribution)
)

// AttestationData wraps the eth2 attestation data and adds the original duty.
// The original duty allows mapping the partial signed response from the VC
// back to the validator pubkey via the aggregation bits field.
type AttestationData struct {
	Data eth2p0.AttestationData
	Duty eth2v1.AttesterDuty
}

func (a AttestationData) Clone() (UnsignedData, error) {
	var resp AttestationData
	err := cloneJSONMarshaler(a, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone attestation")
	}

	return resp, nil
}

func (a AttestationData) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(attestationDataJSON{
		Data: &a.Data,
		Duty: &a.Duty,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal attestation")
	}

	return resp, nil
}

func (a *AttestationData) UnmarshalJSON(data []byte) error {
	var att attestationDataJSON
	if err := json.Unmarshal(data, &att); err != nil {
		return errors.Wrap(err, "unmarshal attestation")
	}

	a.Data = *att.Data
	a.Duty = *att.Duty

	return nil
}

type attestationDataJSON struct {
	Data *eth2p0.AttestationData `json:"attestation_data"`
	Duty *eth2v1.AttesterDuty    `json:"attestation_duty"`
}

// NewAggregatedAttestation returns a new aggregated attestation.
func NewAggregatedAttestation(att *eth2p0.Attestation) AggregatedAttestation {
	return AggregatedAttestation{Attestation: *att}
}

// AggregatedAttestation wraps un unsigned aggregated attestation and implements the UnsignedData interface.
type AggregatedAttestation struct {
	eth2p0.Attestation
}

func (a AggregatedAttestation) Clone() (UnsignedData, error) {
	var resp AggregatedAttestation
	err := cloneJSONMarshaler(a, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone aggregated attestation")
	}

	return resp, nil
}

func (a AggregatedAttestation) MarshalJSON() ([]byte, error) {
	return a.Attestation.MarshalJSON()
}

func (a *AggregatedAttestation) UnmarshalJSON(input []byte) error {
	var att eth2p0.Attestation
	if err := json.Unmarshal(input, &att); err != nil {
		return errors.Wrap(err, "unmarshal aggregated attestation")
	}

	*a = AggregatedAttestation{Attestation: att}

	return nil
}

func (a AggregatedAttestation) MarshalSSZ() ([]byte, error) {
	return a.Attestation.MarshalSSZ()
}

func (a AggregatedAttestation) MarshalSSZTo(dst []byte) ([]byte, error) {
	return a.Attestation.MarshalSSZTo(dst)
}

func (a AggregatedAttestation) SizeSSZ() int {
	return a.Attestation.SizeSSZ()
}

func (a *AggregatedAttestation) UnmarshalSSZ(b []byte) error {
	return a.Attestation.UnmarshalSSZ(b)
}

// NewVersionedProposal validates and returns a new wrapped VersionedProposal.
func NewVersionedProposal(proposal *eth2api.VersionedProposal) (VersionedProposal, error) {
	switch proposal.Version {
	case eth2spec.DataVersionPhase0:
		if proposal.Phase0 == nil {
			return VersionedProposal{}, errors.New("no phase0 block")
		}
	case eth2spec.DataVersionAltair:
		if proposal.Altair == nil {
			return VersionedProposal{}, errors.New("no altair block")
		}
	case eth2spec.DataVersionBellatrix:
		if proposal.Bellatrix == nil {
			return VersionedProposal{}, errors.New("no bellatrix block")
		}
	case eth2spec.DataVersionCapella:
		if proposal.Capella == nil {
			return VersionedProposal{}, errors.New("no capella block")
		}
	case eth2spec.DataVersionDeneb:
		if proposal.Deneb == nil {
			return VersionedProposal{}, errors.New("no deneb block")
		}
	default:
		return VersionedProposal{}, errors.New("unknown version")
	}

	return VersionedProposal{VersionedProposal: *proposal}, nil
}

// VersionedProposal wraps the eth2 versioned proposal and implements UnsignedData.
type VersionedProposal struct {
	eth2api.VersionedProposal
}

func (p VersionedProposal) Clone() (UnsignedData, error) {
	var resp VersionedProposal
	err := cloneJSONMarshaler(p, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone block")
	}

	return resp, nil
}

func (p VersionedProposal) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch p.Version {
	// No block nil checks since `NewVersionedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		marshaller = p.Phase0
	case eth2spec.DataVersionAltair:
		marshaller = p.Altair
	case eth2spec.DataVersionBellatrix:
		marshaller = p.Bellatrix
	case eth2spec.DataVersionCapella:
		marshaller = p.Capella
	case eth2spec.DataVersionDeneb:
		marshaller = p.Deneb
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
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (p *VersionedProposal) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := eth2api.VersionedProposal{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.DataVersionPhase0:
		block := new(eth2p0.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case eth2spec.DataVersionAltair:
		block := new(altair.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case eth2spec.DataVersionBellatrix:
		block := new(bellatrix.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	case eth2spec.DataVersionCapella:
		block := new(capella.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal capella")
		}
		resp.Capella = block
	case eth2spec.DataVersionDeneb:
		block := new(eth2deneb.BlockContents)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal deneb")
		}
		resp.Deneb = block
	default:
		return errors.New("unknown version")
	}

	*p = VersionedProposal{VersionedProposal: resp}

	return nil
}

// NewVersionedBlindedProposal validates and returns a new wrapped VersionedBlindedProposal.
func NewVersionedBlindedProposal(proposal *eth2api.VersionedBlindedProposal) (VersionedBlindedProposal, error) {
	switch proposal.Version {
	case eth2spec.DataVersionBellatrix:
		if proposal.Bellatrix == nil {
			return VersionedBlindedProposal{}, errors.New("no bellatrix blinded proposal")
		}
	case eth2spec.DataVersionCapella:
		if proposal.Capella == nil {
			return VersionedBlindedProposal{}, errors.New("no capella blinded proposal")
		}
	case eth2spec.DataVersionDeneb:
		if proposal.Deneb == nil {
			return VersionedBlindedProposal{}, errors.New("no deneb blinded proposal")
		}
	default:
		return VersionedBlindedProposal{}, errors.New("unknown version")
	}

	return VersionedBlindedProposal{VersionedBlindedProposal: *proposal}, nil
}

// VersionedBlindedProposal wraps the eth2 versioned blinded proposal and implements UnsignedData.
type VersionedBlindedProposal struct {
	eth2api.VersionedBlindedProposal
}

func (p VersionedBlindedProposal) Clone() (UnsignedData, error) {
	var resp VersionedBlindedProposal
	err := cloneJSONMarshaler(p, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone block")
	}

	return resp, nil
}

func (p VersionedBlindedProposal) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch p.Version {
	// No block nil checks since `NewVersionedSignedBlindedBeaconBlock` assumed.
	case eth2spec.DataVersionBellatrix:
		marshaller = p.Bellatrix
	case eth2spec.DataVersionCapella:
		marshaller = p.Capella
	case eth2spec.DataVersionDeneb:
		marshaller = p.Deneb
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

func (p *VersionedBlindedProposal) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := eth2api.VersionedBlindedProposal{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.DataVersionBellatrix:
		block := new(eth2bellatrix.BlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	case eth2spec.DataVersionCapella:
		block := new(eth2capella.BlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal capella")
		}
		resp.Capella = block
	case eth2spec.DataVersionDeneb:
		block := new(eth2deneb.BlindedBeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal deneb")
		}
		resp.Deneb = block
	default:
		return errors.New("unknown version")
	}

	*p = VersionedBlindedProposal{VersionedBlindedProposal: resp}

	return nil
}

// NewVersionedUniversalProposal validates and returns a new wrapped VersionedUniversalProposal.
func NewVersionedUniversalProposal(proposal *eth2api.VersionedUniversalProposal) (VersionedUniversalProposal, error) {
	return VersionedUniversalProposal{VersionedUniversalProposal: *proposal}, nil
}

// VersionedUniversalProposal wraps the eth2 versioned proposal and implements UnsignedData.
type VersionedUniversalProposal struct {
	eth2api.VersionedUniversalProposal
}

func (p VersionedUniversalProposal) Clone() (UnsignedData, error) {
	var resp VersionedUniversalProposal
	err := cloneJSONMarshaler(p, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone universal proposal")
	}

	return resp, nil
}

func (p VersionedUniversalProposal) MarshalJSON() ([]byte, error) {
	if p.Full != nil {
		fp, err := NewVersionedProposal(p.Full)
		if err != nil {
			return nil, err
		}

		return fp.MarshalJSON()
	}

	if p.Blinded != nil {
		bp, err := NewVersionedBlindedProposal(p.Blinded)
		if err != nil {
			return nil, err
		}
		return bp.MarshalJSON()
	}

	return nil, errors.New("no full or blinded block")
}

func (p *VersionedUniversalProposal) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal universal block")
	}

	if raw.Blinded {
		var bp VersionedBlindedProposal
		if err := bp.UnmarshalJSON(input); err != nil {
			return err
		}

		p.Blinded = &eth2api.VersionedBlindedProposal{
			Version:   bp.Version,
			Bellatrix: bp.Bellatrix,
			Capella:   bp.Capella,
			Deneb:     bp.Deneb,
		}
	} else {
		var fp VersionedProposal
		if err := fp.UnmarshalJSON(input); err != nil {
			return err
		}

		p.Full = &eth2api.VersionedProposal{
			Version:   fp.Version,
			Phase0:    fp.Phase0,
			Altair:    fp.Altair,
			Bellatrix: fp.Bellatrix,
			Capella:   fp.Capella,
			Deneb:     fp.Deneb,
		}
	}

	return nil
}

// NewSyncContribution returns a new SyncContribution.
func NewSyncContribution(c *altair.SyncCommitteeContribution) SyncContribution {
	return SyncContribution{SyncCommitteeContribution: *c}
}

type SyncContribution struct {
	altair.SyncCommitteeContribution
}

func (s SyncContribution) Clone() (UnsignedData, error) {
	var resp SyncContribution
	err := cloneJSONMarshaler(s, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone sync contribution")
	}

	return resp, err
}

func (s SyncContribution) MarshalJSON() ([]byte, error) {
	return s.SyncCommitteeContribution.MarshalJSON()
}

func (s *SyncContribution) UnmarshalJSON(input []byte) error {
	return s.SyncCommitteeContribution.UnmarshalJSON(input)
}

func (s SyncContribution) MarshalSSZ() ([]byte, error) {
	return s.SyncCommitteeContribution.MarshalSSZ()
}

func (s SyncContribution) MarshalSSZTo(dst []byte) ([]byte, error) {
	return s.SyncCommitteeContribution.MarshalSSZTo(dst)
}

func (s SyncContribution) SizeSSZ() int {
	return s.SyncCommitteeContribution.SizeSSZ()
}

func (s *SyncContribution) UnmarshalSSZ(b []byte) error {
	return s.SyncCommitteeContribution.UnmarshalSSZ(b)
}

// unmarshalUnsignedData returns an instantiated unsigned data based on the duty type.
func unmarshalUnsignedData(typ DutyType, data []byte) (UnsignedData, error) {
	switch typ {
	case DutyAttester:
		var resp AttestationData
		if err := unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal attestation data")
		}

		return resp, nil
	case DutyProposer:
		var resp VersionedProposal
		if err := unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal proposal")
		}

		return resp, nil
	case DutyBuilderProposer:
		var resp VersionedBlindedProposal
		if err := unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal blinded proposal")
		}

		return resp, nil
	case DutyAggregator:
		var resp AggregatedAttestation
		if err := unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal aggregated attestation")
		}

		return resp, nil
	case DutySyncContribution:
		var resp SyncContribution
		if err := unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal sync contribution")
		}

		return resp, nil
	default:
		return nil, errors.New("unsupported unsigned data duty type")
	}
}
