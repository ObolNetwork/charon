// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// VersionedSignedBeaconBlockDeneb contains a versioned signed beacon block with new deneb.BlockContents.
// This is a placeholder struct until spec.VersionedSignedBeaconBlock includes deneb.BlockContents.
type VersionedSignedBeaconBlockDeneb struct {
	Version   spec.DataVersion
	Phase0    *phase0.SignedBeaconBlock
	Altair    *altair.SignedBeaconBlock
	Bellatrix *bellatrix.SignedBeaconBlock
	Capella   *capella.SignedBeaconBlock
	Deneb     *deneb.SignedBlockContents
}

// Slot returns the slot of the signed beacon block.
func (v *VersionedSignedBeaconBlockDeneb) Slot() (phase0.Slot, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil || v.Phase0.Message == nil {
			return 0, errors.New("no phase0 block")
		}
		return v.Phase0.Message.Slot, nil
	case spec.DataVersionAltair:
		if v.Altair == nil || v.Altair.Message == nil {
			return 0, errors.New("no altair block")
		}
		return v.Altair.Message.Slot, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil {
			return 0, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Slot, nil
	case spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil {
			return 0, errors.New("no capella block")
		}
		return v.Capella.Message.Slot, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil || v.Deneb.SignedBlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Slot, nil
	default:
		return 0, errors.New("unknown version")
	}
}

// ExecutionBlockHash returns the block hash of the beacon block.
func (v *VersionedSignedBeaconBlock) ExecutionBlockHash() (phase0.Hash32, error) {
	switch v.Version {
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil || v.Bellatrix.Message.Body == nil || v.Bellatrix.Message.Body.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.ExecutionPayload.BlockHash, nil
	case spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil || v.Capella.Message.Body == nil || v.Capella.Message.Body.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no capella block")
		}
		return v.Bellatrix.Message.Body.ExecutionPayload.BlockHash, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil ||
			v.Deneb.SignedBlock.Message.Body == nil || v.Deneb.SignedBlock.Message.Body.ExecutionPayload == nil || v.Deneb.SignedBlobSidecars == nil {
			return phase0.Hash32{}, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.ExecutionPayload.BlockHash, nil
	default:
		return phase0.Hash32{}, errors.New("unknown version")
	}
}

// Attestations returns the attestations of the beacon block.
func (v *VersionedSignedBeaconBlock) Attestations() ([]*phase0.Attestation, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil || v.Phase0.Message == nil || v.Phase0.Message.Body == nil {
			return nil, errors.New("no phase0 block")
		}
		return v.Phase0.Message.Body.Attestations, nil
	case spec.DataVersionAltair:
		if v.Altair == nil || v.Altair.Message == nil || v.Altair.Message.Body == nil {
			return nil, errors.New("no altair block")
		}
		return v.Altair.Message.Body.Attestations, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil || v.Bellatrix.Message.Body == nil {
			return nil, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.Attestations, nil
	case spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil || v.Capella.Message.Body == nil {
			return nil, errors.New("no capella block")
		}
		return v.Capella.Message.Body.Attestations, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock.Message == nil || v.Deneb.SignedBlock.Message.Body == nil {
			return nil, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.Attestations, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// Root returns the root of the beacon block.
func (v *VersionedSignedBeaconBlock) Root() (phase0.Root, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return phase0.Root{}, errors.New("no phase0 block")
		}
		return v.Phase0.Message.HashTreeRoot()
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return phase0.Root{}, errors.New("no altair block")
		}
		return v.Altair.Message.HashTreeRoot()
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.HashTreeRoot()
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no capella block")
		}
		return v.Capella.Message.HashTreeRoot()
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return phase0.Root{}, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.HashTreeRoot()
	default:
		return phase0.Root{}, errors.New("unknown version")
	}
}

// BodyRoot returns the body root of the beacon block.
func (v *VersionedSignedBeaconBlock) BodyRoot() (phase0.Root, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return phase0.Root{}, errors.New("no phase0 block")
		}
		return v.Phase0.Message.Body.HashTreeRoot()
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return phase0.Root{}, errors.New("no altair block")
		}
		return v.Altair.Message.Body.HashTreeRoot()
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.HashTreeRoot()
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no capella block")
		}
		return v.Capella.Message.Body.HashTreeRoot()
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return phase0.Root{}, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.HashTreeRoot()
	default:
		return phase0.Root{}, errors.New("unknown version")
	}
}

// ParentRoot returns the parent root of the beacon block.
func (v *VersionedSignedBeaconBlock) ParentRoot() (phase0.Root, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return phase0.Root{}, errors.New("no phase0 block")
		}
		return v.Phase0.Message.ParentRoot, nil
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return phase0.Root{}, errors.New("no altair block")
		}
		return v.Altair.Message.ParentRoot, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.ParentRoot, nil
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no capella block")
		}
		return v.Capella.Message.ParentRoot, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return phase0.Root{}, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.ParentRoot, nil
	default:
		return phase0.Root{}, errors.New("unknown version")
	}
}

// StateRoot returns the state root of the beacon block.
func (v *VersionedSignedBeaconBlock) StateRoot() (phase0.Root, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return phase0.Root{}, errors.New("no phase0 block")
		}
		return v.Phase0.Message.StateRoot, nil
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return phase0.Root{}, errors.New("no altair block")
		}
		return v.Altair.Message.StateRoot, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return phase0.Root{}, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.StateRoot, nil
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return phase0.Root{}, errors.New("no capella block")
		}
		return v.Capella.Message.StateRoot, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return phase0.Root{}, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.StateRoot, nil
	default:
		return phase0.Root{}, errors.New("unknown version")
	}
}

// AttesterSlashings returns the attester slashings of the beacon block.
func (v *VersionedSignedBeaconBlock) AttesterSlashings() ([]*phase0.AttesterSlashing, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return nil, errors.New("no phase0 block")
		}
		return v.Phase0.Message.Body.AttesterSlashings, nil
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return nil, errors.New("no altair block")
		}
		return v.Altair.Message.Body.AttesterSlashings, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.AttesterSlashings, nil
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella block")
		}
		return v.Capella.Message.Body.AttesterSlashings, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return nil, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.AttesterSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// ProposerSlashings returns the proposer slashings of the beacon block.
func (v *VersionedSignedBeaconBlock) ProposerSlashings() ([]*phase0.ProposerSlashing, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return nil, errors.New("no phase0 block")
		}
		return v.Phase0.Message.Body.ProposerSlashings, nil
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return nil, errors.New("no altair block")
		}
		return v.Altair.Message.Body.ProposerSlashings, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.ProposerSlashings, nil
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella block")
		}
		return v.Capella.Message.Body.ProposerSlashings, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return nil, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.ProposerSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// SyncAggregate returns the sync aggregate of the beacon block.
func (v *VersionedSignedBeaconBlock) SyncAggregate() (*altair.SyncAggregate, error) {
	switch v.Version {
	case spec.DataVersionPhase0:
		return nil, errors.New("phase0 block does not have sync aggregate")
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return nil, errors.New("no altair block")
		}
		return v.Altair.Message.Body.SyncAggregate, nil
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}
		return v.Bellatrix.Message.Body.SyncAggregate, nil
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella block")
		}
		return v.Capella.Message.Body.SyncAggregate, nil
	case spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlock == nil || v.Deneb.SignedBlock.Message == nil {
			return nil, errors.New("no deneb block")
		}
		return v.Deneb.SignedBlock.Message.Body.SyncAggregate, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// String returns a string version of the structure.
func (v *VersionedSignedBeaconBlock) String() string {
	switch v.Version {
	case spec.DataVersionPhase0:
		if v.Phase0 == nil {
			return ""
		}
		return v.Phase0.String()
	case spec.DataVersionAltair:
		if v.Altair == nil {
			return ""
		}
		return v.Altair.String()
	case spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return ""
		}
		return v.Bellatrix.String()
	case spec.DataVersionCapella:
		if v.Capella == nil {
			return ""
		}
		return v.Capella.String()
	case spec.DataVersionDeneb:
		if v.Deneb == nil {
			return ""
		}
		return v.Deneb.String()
	default:
		return "unknown version"
	}
}
