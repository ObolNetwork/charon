// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package denebcharon

import (
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// VersionedSignedBlindedBeaconBlock contains a versioned signed blinded beacon block.
type VersionedSignedBlindedBeaconBlock struct {
	Version   eth2spec.DataVersion
	Bellatrix *eth2bellatrix.SignedBlindedBeaconBlock
	Capella   *eth2capella.SignedBlindedBeaconBlock
	Deneb     *eth2deneb.SignedBlindedBlockContents
}

// Slot returns the slot of the signed beacon block.
func (v *VersionedSignedBlindedBeaconBlock) Slot() (eth2p0.Slot, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil {
			return 0, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Slot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil {
			return 0, errors.New("no capella block")
		}

		return v.Capella.Message.Slot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Slot, nil
	default:
		return 0, errors.New("unsupported version")
	}
}

// Attestations returns the attestations of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) Attestations() ([]*eth2p0.Attestation, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil || v.Bellatrix.Message.Body == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.Attestations, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil || v.Capella.Message.Body == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Message.Body.Attestations, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.Attestations, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// Root returns the root of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) Root() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.Message.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.HashTreeRoot()
	default:
		return eth2p0.Root{}, errors.New("unsupported version")
	}
}

// BodyRoot returns the body root of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) BodyRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.Message.Body.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.HashTreeRoot()
	default:
		return eth2p0.Root{}, errors.New("unsupported version")
	}
}

// ParentRoot returns the parent root of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) ParentRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.ParentRoot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.Message.ParentRoot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.ParentRoot, nil
	default:
		return eth2p0.Root{}, errors.New("unsupported version")
	}
}

// StateRoot returns the state root of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) StateRoot() (eth2p0.Root, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.Root{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.StateRoot, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.Root{}, errors.New("no capella block")
		}

		return v.Capella.Message.StateRoot, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.Root{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.StateRoot, nil
	default:
		return eth2p0.Root{}, errors.New("unsupported version")
	}
}

// AttesterSlashings returns the attester slashings of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) AttesterSlashings() ([]*eth2p0.AttesterSlashing, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.AttesterSlashings, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Message.Body.AttesterSlashings, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.AttesterSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// ProposerSlashings returns the proposer slashings of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) ProposerSlashings() ([]*eth2p0.ProposerSlashing, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return nil, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.ProposerSlashings, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return nil, errors.New("no capella block")
		}

		return v.Capella.Message.Body.ProposerSlashings, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil {
			return nil, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.ProposerSlashings, nil
	default:
		return nil, errors.New("unknown version")
	}
}

// ProposerIndex returns the proposer index of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) ProposerIndex() (eth2p0.ValidatorIndex, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil {
			return 0, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.ProposerIndex, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil {
			return 0, errors.New("no capella block")
		}

		return v.Capella.Message.ProposerIndex, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.ProposerIndex, nil
	default:
		return 0, errors.New("unknown version")
	}
}

// ExecutionBlockHash returns the hash of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) ExecutionBlockHash() (eth2p0.Hash32, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil || v.Bellatrix.Message.Body == nil || v.Bellatrix.Message.Body.ExecutionPayloadHeader == nil {
			return eth2p0.Hash32{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil || v.Capella.Message.Body == nil || v.Capella.Message.Body.ExecutionPayloadHeader == nil {
			return eth2p0.Hash32{}, errors.New("no capella block")
		}

		return v.Capella.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message.Body == nil || v.Deneb.SignedBlindedBlock.Message.Body.ExecutionPayloadHeader == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.Hash32{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	default:
		return eth2p0.Hash32{}, errors.New("unknown version")
	}
}

// ExecutionBlockNumber returns the block number of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) ExecutionBlockNumber() (uint64, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil || v.Bellatrix.Message == nil || v.Bellatrix.Message.Body == nil || v.Bellatrix.Message.Body.ExecutionPayloadHeader == nil {
			return 0, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil || v.Capella.Message == nil || v.Capella.Message.Body == nil || v.Capella.Message.Body.ExecutionPayloadHeader == nil {
			return 0, errors.New("no capella block")
		}

		return v.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlock.Message.Body == nil || v.Deneb.SignedBlindedBlock.Message.Body.ExecutionPayloadHeader == nil || v.Deneb.SignedBlindedBlock.Message == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return 0, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Message.Body.ExecutionPayloadHeader.BlockNumber, nil
	default:
		return 0, errors.New("unknown version")
	}
}

// Signature returns the signature of the beacon block.
func (v *VersionedSignedBlindedBeaconBlock) Signature() (eth2p0.BLSSignature, error) {
	switch v.Version {
	case eth2spec.DataVersionBellatrix:
		if v.Bellatrix == nil {
			return eth2p0.BLSSignature{}, errors.New("no bellatrix block")
		}

		return v.Bellatrix.Signature, nil
	case eth2spec.DataVersionCapella:
		if v.Capella == nil {
			return eth2p0.BLSSignature{}, errors.New("no capella block")
		}

		return v.Capella.Signature, nil
	case eth2spec.DataVersionDeneb:
		if v.Deneb == nil || v.Deneb.SignedBlindedBlock == nil || v.Deneb.SignedBlindedBlobSidecars == nil {
			return eth2p0.BLSSignature{}, errors.New("no deneb block")
		}

		return v.Deneb.SignedBlindedBlock.Signature, nil
	default:
		return eth2p0.BLSSignature{}, errors.New("unknown version")
	}
}
