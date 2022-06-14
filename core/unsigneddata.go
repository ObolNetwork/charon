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

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

var (
	_ UnsignedData = AttestationData{}
	_ UnsignedData = VersionedBeaconBlock{}
)

// AttestationData wraps the eth2 attestation data and adds the original duty.
// The original duty allows mapping the partial signed response from the VC
// backed to the validator pubkey via the aggregation bits field.
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

// NewVersionedBeaconBlock validates and returns a new wrapped VersionedBeaconBlock.
func NewVersionedBeaconBlock(block *spec.VersionedBeaconBlock) (VersionedBeaconBlock, error) {
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0 == nil {
			return VersionedBeaconBlock{}, errors.New("no phase0 block")
		}
	case spec.DataVersionAltair:
		if block.Altair == nil {
			return VersionedBeaconBlock{}, errors.New("no altair block")
		}
	case spec.DataVersionBellatrix:
		if block.Bellatrix == nil {
			return VersionedBeaconBlock{}, errors.New("no bellatrix block")
		}
	default:
		return VersionedBeaconBlock{}, errors.New("unknown version")
	}

	return VersionedBeaconBlock{VersionedBeaconBlock: *block}, nil
}

type VersionedBeaconBlock struct {
	spec.VersionedBeaconBlock
}

func (b VersionedBeaconBlock) Clone() (UnsignedData, error) {
	var resp VersionedBeaconBlock
	err := cloneJSONMarshaler(b, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "clone block")
	}

	return resp, nil
}

func (b VersionedBeaconBlock) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch b.Version {
	// No block nil checks since `NewVersionedSignedBeaconBlock` assumed.
	case spec.DataVersionPhase0:
		marshaller = b.Phase0
	case spec.DataVersionAltair:
		marshaller = b.Altair
	case spec.DataVersionBellatrix:
		marshaller = b.Bellatrix
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

func (b *VersionedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := spec.VersionedBeaconBlock{Version: spec.DataVersion(raw.Version)}
	switch resp.Version {
	case spec.DataVersionPhase0:
		block := new(eth2p0.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal phase0")
		}
		resp.Phase0 = block
	case spec.DataVersionAltair:
		block := new(altair.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal altair")
		}
		resp.Altair = block
	case spec.DataVersionBellatrix:
		block := new(bellatrix.BeaconBlock)
		if err := json.Unmarshal(raw.Block, &block); err != nil {
			return errors.Wrap(err, "unmarshal bellatrix")
		}
		resp.Bellatrix = block
	default:
		return errors.New("unknown version")
	}

	*b = VersionedBeaconBlock{VersionedBeaconBlock: resp}

	return nil
}

// UnmarshalUnsignedData returns an instantiated unsigned data based on the duty type.
// TODO(corver): Unexport once leadercast is removed or uses protobufs.
func UnmarshalUnsignedData(typ DutyType, data []byte) (UnsignedData, error) {
	switch typ {
	case DutyAttester:
		var resp AttestationData
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal attestation data")
		}

		return resp, nil
	case DutyProposer:
		var resp VersionedBeaconBlock
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, errors.Wrap(err, "unmarshal block")
		}

		return resp, nil
	default:
		return nil, errors.New("unsupported unsigned data duty type")
	}
}
