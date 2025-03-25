// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"encoding/json"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2e "github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

var (
	_ UnsignedData = AttestationData{}
	_ UnsignedData = AggregatedAttestation{}
	_ UnsignedData = VersionedAggregatedAttestation{}
	_ UnsignedData = VersionedProposal{}
	_ UnsignedData = SyncContribution{}

	// Some types also support SSZ marshalling and unmarshalling.
	_ ssz.Marshaler   = AttestationData{}
	_ ssz.Marshaler   = AggregatedAttestation{}
	_ ssz.Marshaler   = VersionedAggregatedAttestation{}
	_ ssz.Marshaler   = VersionedProposal{}
	_ ssz.Marshaler   = SyncContribution{}
	_ ssz.Unmarshaler = new(AttestationData)
	_ ssz.Unmarshaler = new(AggregatedAttestation)
	_ ssz.Unmarshaler = new(VersionedAggregatedAttestation)
	_ ssz.Unmarshaler = new(VersionedProposal)
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

// NewVersionedAggregatedAttestation returns a new aggregated attestation.
func NewVersionedAggregatedAttestation(att *eth2spec.VersionedAttestation) (VersionedAggregatedAttestation, error) {
	switch att.Version {
	case eth2spec.DataVersionPhase0:
		if att.Phase0 == nil {
			return VersionedAggregatedAttestation{}, errors.New("no phase0 attestation")
		}
	case eth2spec.DataVersionAltair:
		if att.Altair == nil {
			return VersionedAggregatedAttestation{}, errors.New("no altair attestation")
		}
	case eth2spec.DataVersionBellatrix:
		if att.Bellatrix == nil {
			return VersionedAggregatedAttestation{}, errors.New("no bellatrix attestation")
		}
	case eth2spec.DataVersionCapella:
		if att.Capella == nil {
			return VersionedAggregatedAttestation{}, errors.New("no capella attestation")
		}
	case eth2spec.DataVersionDeneb:
		if att.Deneb == nil {
			return VersionedAggregatedAttestation{}, errors.New("no deneb attestation")
		}
	case eth2spec.DataVersionElectra:
		if att.Electra == nil {
			return VersionedAggregatedAttestation{}, errors.New("no electra attestation")
		}
	default:
		return VersionedAggregatedAttestation{}, errors.New("unknown version")
	}

	return VersionedAggregatedAttestation{VersionedAttestation: *att}, nil
}

// VersionedAggregatedAttestation wraps un unsigned aggregated attestation and implements the UnsignedData interface.
type VersionedAggregatedAttestation struct {
	eth2spec.VersionedAttestation
}

func (a VersionedAggregatedAttestation) Clone() (UnsignedData, error) {
	var resp VersionedAggregatedAttestation
	err := cloneJSONMarshaler(a, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone aggregated attestation")
	}

	return resp, nil
}

func (a VersionedAggregatedAttestation) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch a.Version {
	// No aggregatedAttestation nil checks since `NewVersionedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		marshaller = a.Phase0
	case eth2spec.DataVersionAltair:
		marshaller = a.Altair
	case eth2spec.DataVersionBellatrix:
		marshaller = a.Bellatrix
	case eth2spec.DataVersionCapella:
		marshaller = a.Capella
	case eth2spec.DataVersionDeneb:
		marshaller = a.Deneb
	case eth2spec.DataVersionElectra:
		marshaller = a.Electra
	default:
		return nil, errors.New("unknown version")
	}

	aggregatedAttestation, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal aggregatedAttestation")
	}

	version, err := eth2util.DataVersionFromETH2(a.Version)
	if err != nil {
		return nil, errors.Wrap(err, "convert version")
	}

	resp, err := json.Marshal(versionedRawAttestationJSON{
		Version:        version,
		ValidatorIndex: a.ValidatorIndex,
		Attestation:    aggregatedAttestation,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal wrapper")
	}

	return resp, nil
}

func (a VersionedAggregatedAttestation) HashTreeRoot() ([32]byte, error) {
	switch a.Version {
	// No aggregatedAttestation nil checks since `NewVersionedProposal` assumed.
	case eth2spec.DataVersionPhase0:
		return a.Phase0.HashTreeRoot()
	case eth2spec.DataVersionAltair:
		return a.Altair.HashTreeRoot()
	case eth2spec.DataVersionBellatrix:
		return a.Bellatrix.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		return a.Capella.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		return a.Deneb.HashTreeRoot()
	case eth2spec.DataVersionElectra:
		return a.Electra.HashTreeRoot()
	default:
		return [32]byte{}, errors.New("unknown version")
	}
}

func (a *VersionedAggregatedAttestation) UnmarshalJSON(input []byte) error {
	var raw versionedRawAttestationJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal attestation")
	}

	resp := eth2spec.VersionedAttestation{Version: raw.Version.ToETH2()}
	switch resp.Version {
	case eth2spec.DataVersionPhase0:
		att := new(eth2p0.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = att
	case eth2spec.DataVersionAltair:
		att := new(eth2p0.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = att
	case eth2spec.DataVersionBellatrix:
		att := new(eth2p0.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = att
	case eth2spec.DataVersionCapella:
		att := new(eth2p0.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal capella")
		}
		resp.Capella = att
	case eth2spec.DataVersionDeneb:
		att := new(eth2p0.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal deneb")
		}
		resp.Deneb = att
	case eth2spec.DataVersionElectra:
		att := new(eth2e.Attestation)
		err := json.Unmarshal(raw.Attestation, &att)
		if err != nil {
			return errors.Wrap(err, "unmarshal electra")
		}
		resp.Electra = att
	default:
		return errors.New("unknown attestation version", z.Str("version", a.Version.String()))
	}
	resp.ValidatorIndex = raw.ValidatorIndex

	a.VersionedAttestation = resp

	return nil
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
		if proposal.Bellatrix == nil && !proposal.Blinded {
			return VersionedProposal{}, errors.New("no bellatrix block")
		}
		if proposal.BellatrixBlinded == nil && proposal.Blinded {
			return VersionedProposal{}, errors.New("no bellatrix blinded block")
		}
	case eth2spec.DataVersionCapella:
		if proposal.Capella == nil && !proposal.Blinded {
			return VersionedProposal{}, errors.New("no capella block")
		}
		if proposal.CapellaBlinded == nil && proposal.Blinded {
			return VersionedProposal{}, errors.New("no capella blinded block")
		}
	case eth2spec.DataVersionDeneb:
		if proposal.Deneb == nil && !proposal.Blinded {
			return VersionedProposal{}, errors.New("no deneb block")
		}
		if proposal.DenebBlinded == nil && proposal.Blinded {
			return VersionedProposal{}, errors.New("no deneb blinded block")
		}
	case eth2spec.DataVersionElectra:
		if proposal.Electra == nil && !proposal.Blinded {
			return VersionedProposal{}, errors.New("no electra block")
		}
		if proposal.ElectraBlinded == nil && proposal.Blinded {
			return VersionedProposal{}, errors.New("no electra blinded block")
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
		if p.Blinded {
			marshaller = p.BellatrixBlinded
		} else {
			marshaller = p.Bellatrix
		}
	case eth2spec.DataVersionCapella:
		if p.Blinded {
			marshaller = p.CapellaBlinded
		} else {
			marshaller = p.Capella
		}
	case eth2spec.DataVersionDeneb:
		if p.Blinded {
			marshaller = p.DenebBlinded
		} else {
			marshaller = p.Deneb
		}
	case eth2spec.DataVersionElectra:
		if p.Blinded {
			marshaller = p.ElectraBlinded
		} else {
			marshaller = p.Electra
		}
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
		Blinded: p.Blinded,
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

	resp := eth2api.VersionedProposal{
		Version: raw.Version.ToETH2(),
		Blinded: raw.Blinded,
	}

	switch resp.Version {
	case eth2spec.DataVersionPhase0:
		if raw.Blinded {
			return errors.New("phase0 block cannot be blinded")
		}
		block := new(eth2p0.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case eth2spec.DataVersionAltair:
		if raw.Blinded {
			return errors.New("altair block cannot be blinded")
		}
		block := new(altair.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case eth2spec.DataVersionBellatrix:
		if raw.Blinded {
			block := new(eth2bellatrix.BlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal bellatrix blinded")
			}
			resp.BellatrixBlinded = block
		} else {
			block := new(bellatrix.BeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal bellatrix")
			}
			resp.Bellatrix = block
		}
	case eth2spec.DataVersionCapella:
		if raw.Blinded {
			block := new(eth2capella.BlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal capella blinded")
			}
			resp.CapellaBlinded = block
		} else {
			block := new(capella.BeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal capella")
			}
			resp.Capella = block
		}
	case eth2spec.DataVersionDeneb:
		if raw.Blinded {
			block := new(eth2deneb.BlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal deneb blinded")
			}
			resp.DenebBlinded = block
		} else {
			block := new(eth2deneb.BlockContents)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal deneb")
			}
			resp.Deneb = block
		}
	case eth2spec.DataVersionElectra:
		if raw.Blinded {
			block := new(eth2electra.BlindedBeaconBlock)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal electra blinded")
			}
			resp.ElectraBlinded = block
		} else {
			block := new(eth2electra.BlockContents)
			if err := json.Unmarshal(raw.Block, &block); err != nil {
				return errors.Wrap(err, "unmarshal electra")
			}
			resp.Electra = block
		}
	default:
		return errors.New("unknown version")
	}

	*p = VersionedProposal{VersionedProposal: resp}

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

	return resp, nil
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
	case DutyAggregator:
		var respVersioned VersionedAggregatedAttestation
		if err := unmarshal(data, &respVersioned); err != nil {
			var resp AggregatedAttestation
			if err := unmarshal(data, &resp); err != nil {
				return nil, errors.Wrap(err, "unmarshal aggregated attestation")
			}

			return resp, nil
		}

		return respVersioned, nil
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
