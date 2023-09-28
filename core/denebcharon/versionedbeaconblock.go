// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package denebcharon

import (
	"encoding/json"

	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util"
)

// VersionedBeaconBlock contains a versioned beacon block.
type VersionedBeaconBlock struct {
	Version   eth2spec.DataVersion
	Phase0    *eth2p0.BeaconBlock
	Altair    *altair.BeaconBlock
	Bellatrix *bellatrix.BeaconBlock
	Capella   *capella.BeaconBlock
	Deneb     *eth2deneb.BlockContents
}

// IsEmpty returns true if there is no block.
func (v *VersionedBeaconBlock) IsEmpty() bool {
	return v.Phase0 == nil && v.Altair == nil && v.Bellatrix == nil && v.Capella == nil && v.Deneb == nil
}

// Slot returns the slot of the beacon block.
func (v *VersionedBeaconBlock) Slot() (eth2p0.Slot, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return 0, errors.New("no phase0 block")
		}

		return v.Phase0.Slot, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return 0, errors.New("no altair block")
		}

		return v.Altair.Slot, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Slot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no capella block")
		}

		return v.Capella.Slot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.BlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}

		return v.Deneb.Block.Slot, nil
	default:
		return 0, errors.New("unknown version")
	}
}

// ProposerIndex returns the proposer index of the beacon block.
func (v *VersionedBeaconBlock) ProposerIndex() (eth2p0.ValidatorIndex, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return 0, errors.New("no phase0 block")
		}

		return v.Phase0.ProposerIndex, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return 0, errors.New("no altair block")
		}

		return v.Altair.ProposerIndex, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return 0, errors.New("no bellatrix block")
		}

		return v.Bellatrix.ProposerIndex, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return 0, errors.New("no capella block")
		}

		return v.Capella.ProposerIndex, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.BlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}

		return v.Deneb.Block.ProposerIndex, nil
	default:
		return 0, errors.New("unknown version")
	}
}

// Root returns the root of the beacon block.
func (v *VersionedBeaconBlock) Root() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return eth2p0.Root{}, errors.New("no phase0 block")
		}

		return v.Phase0.HashTreeRoot()
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return eth2p0.Root{}, errors.New("no altair block")
		}

		return v.Altair.HashTreeRoot()
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.BlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.HashTreeRoot()
	default:
		return eth2p0.Root{}, errors.New("unknown version")
	}
}

// BodyRoot returns the body root of the beacon block.
func (v *VersionedBeaconBlock) BodyRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return eth2p0.Root{}, errors.New("no phase0 block")
		}

		return v.Phase0.Body.HashTreeRoot()
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return eth2p0.Root{}, errors.New("no altair block")
		}

		return v.Altair.Body.HashTreeRoot()
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Body.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.Body.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.BlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.Block.Body.HashTreeRoot()
	default:
		return eth2p0.Root{}, errors.New("unknown version")
	}
}

// ParentRoot returns the parent root of the beacon block.
func (v *VersionedBeaconBlock) ParentRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return eth2p0.Root{}, errors.New("no phase0 block")
		}

		return v.Phase0.ParentRoot, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return eth2p0.Root{}, errors.New("no altair block")
		}

		return v.Altair.ParentRoot, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.ParentRoot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.ParentRoot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.BlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.Block.ParentRoot, nil
	default:
		return eth2p0.Root{}, errors.New("unknown version")
	}
}

// StateRoot returns the state root of the beacon block.
func (v *VersionedBeaconBlock) StateRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return eth2p0.Root{}, errors.New("no phase0 block")
		}

		return v.Phase0.StateRoot, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return eth2p0.Root{}, errors.New("no altair block")
		}

		return v.Altair.StateRoot, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.StateRoot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.StateRoot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.Block.StateRoot, nil
	default:
		return eth2p0.Root{}, errors.New("unknown version")
	}
}

// Attestations returns the attestations of the beacon block.
func (v *VersionedBeaconBlock) Attestations() ([]*eth2p0.Attestation, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil || v.Phase0.Body == nil {
			return nil, errors.New("no phase0 block")
		}

		return v.Phase0.Body.Attestations, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil || v.Altair.Body == nil {
			return nil, errors.New("no altair block")
		}

		return v.Altair.Body.Attestations, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Body == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Body.Attestations, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Body == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Body.Attestations, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.Block.Body == nil || v.Deneb.BlobSidecars == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.Block.Body.Attestations, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// AttesterSlashings returns the attester slashings of the beacon block.
func (v *VersionedBeaconBlock) AttesterSlashings() ([]*eth2p0.AttesterSlashing, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil || v.Phase0.Body == nil {
			return nil, errors.New("no phase0 block")
		}

		return v.Phase0.Body.AttesterSlashings, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil || v.Altair.Body == nil {
			return nil, errors.New("no altair block")
		}

		return v.Altair.Body.AttesterSlashings, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Body == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Body.AttesterSlashings, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Body == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Body.AttesterSlashings, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.Block.Body == nil || v.Deneb.BlobSidecars == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.Block.Body.AttesterSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// ProposerSlashings returns the proposer slashings of the beacon block.
func (v *VersionedBeaconBlock) ProposerSlashings() ([]*eth2p0.ProposerSlashing, error) {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil || v.Phase0.Body == nil {
			return nil, errors.New("no phase0 block")
		}

		return v.Phase0.Body.ProposerSlashings, nil
	case eth2spec.DataVersionAltair:
		if v.Altair == nil || v.Altair.Body == nil {
			return nil, errors.New("no altair block")
		}

		return v.Altair.Body.ProposerSlashings, nil
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Body == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Body.ProposerSlashings, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Body == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Body.ProposerSlashings, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.Block == nil || v.Deneb.Block.Body == nil || v.Deneb.BlobSidecars == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.Block.Body.ProposerSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// String returns a string version of the structure.
func (v *VersionedBeaconBlock) String() string {
	switch v.Version {
	case eth2spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return ""
		}

		return v.Phase0.String()
	case eth2spec.DataVersionAltair:
		if v.Altair == nil {
			return ""
		}

		return v.Altair.String()
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return ""
		}

		return v.Bellatrix.String()
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return ""
		}

		return v.Capella.String()
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil {
			return ""
		}

		return v.Deneb.String()
	default:
		return "unknown version"
	}
}

func (v VersionedBeaconBlock) MarshalJSON() ([]byte, error) {
	var marshaller json.Marshaler
	switch v.Version {
	// No block nil checks since `NewVersionedBeaconBlock` assumed.
	case eth2spec.DataVersionPhase0:
		marshaller = v.Phase0
	case eth2spec.DataVersionAltair:
		marshaller = v.Altair
	case eth2spec.DataVersionBellatrix:
		marshaller = v.Bellatrix
	case eth2spec.DataVersionCapella:
		marshaller = v.Capella
	case eth2spec.DataVersionDeneb:
		marshaller = v.Deneb
	default:
		return nil, errors.New("unknown version")
	}

	block, err := marshaller.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal versioned beacon block")
	}

	version, err := eth2util.DataVersionFromETH2(v.Version)
	if err != nil {
		return nil, errors.Wrap(err, "convert beacon block version")
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

func (v *VersionedBeaconBlock) UnmarshalJSON(input []byte) error {
	var raw versionedRawBlockJSON
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "unmarshal block")
	}

	resp := VersionedBeaconBlock{Version: raw.Version.ToETH2()}
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

	*v = resp

	return nil
}

type versionedRawBlockJSON struct {
	Version eth2util.DataVersion `json:"version"`
	Block   json.RawMessage      `json:"block"`
}
