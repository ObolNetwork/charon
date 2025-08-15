// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
)

// sszType indicates a type that can be marshalled and unmarshalled by ssz.
type sszType interface {
	ssz.Marshaler
	ssz.Unmarshaler
}

// ======================= VersionedSignedProposal =======================

// MarshalSSZ ssz marshals the VersionedSignedProposal object.
func (p VersionedSignedProposal) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(p)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedSignedProposal")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedSignedProposal object to a target array.
func (p VersionedSignedProposal) MarshalSSZTo(buf []byte) ([]byte, error) {
	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid version")
	}

	return marshalSSZVersionedBlindedTo(buf, version, p.Blinded, p.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshals the VersionedSignedProposal object.
func (p *VersionedSignedProposal) UnmarshalSSZ(buf []byte) error {
	version, blinded, err := unmarshalSSZVersionedBlinded(buf, p.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedProposal")
	}

	p.Version = version.ToETH2()
	p.Blinded = blinded

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedSignedProposal object.
func (p VersionedSignedProposal) SizeSSZ() int {
	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	val, err := p.sszValFromVersion(version, p.Blinded)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersionedBlinded(val)
}

// sszValFromVersion returns the internal value of the VersionedSignedProposal object for a given version.
func (p *VersionedSignedProposal) sszValFromVersion(version eth2util.DataVersion, blinded bool) (sszType, error) {
	switch version {
	case eth2util.DataVersionPhase0:
		if p.Phase0 == nil {
			p.Phase0 = new(eth2p0.SignedBeaconBlock)
		}

		return p.Phase0, nil
	case eth2util.DataVersionAltair:
		if p.Altair == nil {
			p.Altair = new(altair.SignedBeaconBlock)
		}

		return p.Altair, nil
	case eth2util.DataVersionBellatrix:
		if p.Bellatrix == nil && !blinded {
			p.Bellatrix = new(bellatrix.SignedBeaconBlock)
		}

		if p.BellatrixBlinded == nil && blinded {
			p.BellatrixBlinded = new(eth2bellatrix.SignedBlindedBeaconBlock)
		}

		if blinded {
			return p.BellatrixBlinded, nil
		}

		return p.Bellatrix, nil
	case eth2util.DataVersionCapella:
		if p.Capella == nil && !blinded {
			p.Capella = new(capella.SignedBeaconBlock)
		}

		if p.CapellaBlinded == nil && blinded {
			p.CapellaBlinded = new(eth2capella.SignedBlindedBeaconBlock)
		}

		if blinded {
			return p.CapellaBlinded, nil
		}

		return p.Capella, nil
	case eth2util.DataVersionDeneb:
		if p.Deneb == nil && !blinded {
			p.Deneb = new(eth2deneb.SignedBlockContents)
		}

		if p.DenebBlinded == nil && blinded {
			p.DenebBlinded = new(eth2deneb.SignedBlindedBeaconBlock)
		}

		if blinded {
			return p.DenebBlinded, nil
		}

		return p.Deneb, nil
	case eth2util.DataVersionElectra:
		if p.Electra == nil && !blinded {
			p.Electra = new(eth2electra.SignedBlockContents)
		}

		if p.ElectraBlinded == nil && blinded {
			p.ElectraBlinded = new(eth2electra.SignedBlindedBeaconBlock)
		}

		if blinded {
			return p.ElectraBlinded, nil
		}

		return p.Electra, nil
	case eth2util.DataVersionFulu:
		if p.Fulu == nil && !blinded {
			p.Fulu = new(eth2electra.SignedBlockContents) // Fulu blocks have the same structure as electra blocks.
		}

		if p.FuluBlinded == nil && blinded {
			p.FuluBlinded = new(eth2electra.SignedBlindedBeaconBlock) // Fulu blinded blocks have the same structure as electra blinded blocks.
		}

		if blinded {
			return p.FuluBlinded, nil
		}

		return p.Fulu, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedProposal ===================

// MarshalSSZ ssz marshals the VersionedProposal object.
func (p VersionedProposal) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(p)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedBeaconBlock")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedProposal object to a target array.
func (p VersionedProposal) MarshalSSZTo(buf []byte) ([]byte, error) {
	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid version")
	}

	return marshalSSZVersionedBlindedTo(buf, version, p.Blinded, p.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshalls the VersionedProposal object.
func (p *VersionedProposal) UnmarshalSSZ(buf []byte) error {
	version, blinded, err := unmarshalSSZVersionedBlinded(buf, p.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedProposal")
	}

	p.Version = version.ToETH2()
	p.Blinded = blinded

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedProposal object.
func (p VersionedProposal) SizeSSZ() int {
	version, err := eth2util.DataVersionFromETH2(p.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	val, err := p.sszValFromVersion(version, p.Blinded)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersionedBlinded(val)
}

// sszValFromVersion returns the internal value of the VersionedBeaconBlock object for a given version.
func (p *VersionedProposal) sszValFromVersion(version eth2util.DataVersion, blinded bool) (sszType, error) {
	switch version {
	case eth2util.DataVersionPhase0:
		if p.Phase0 == nil {
			p.Phase0 = new(eth2p0.BeaconBlock)
		}

		return p.Phase0, nil
	case eth2util.DataVersionAltair:
		if p.Altair == nil {
			p.Altair = new(altair.BeaconBlock)
		}

		return p.Altair, nil
	case eth2util.DataVersionBellatrix:
		if p.Bellatrix == nil && !blinded {
			p.Bellatrix = new(bellatrix.BeaconBlock)
		}

		if p.BellatrixBlinded == nil && blinded {
			p.BellatrixBlinded = new(eth2bellatrix.BlindedBeaconBlock)
		}

		if blinded {
			return p.BellatrixBlinded, nil
		}

		return p.Bellatrix, nil
	case eth2util.DataVersionCapella:
		if p.Capella == nil && !blinded {
			p.Capella = new(capella.BeaconBlock)
		}

		if p.CapellaBlinded == nil && blinded {
			p.CapellaBlinded = new(eth2capella.BlindedBeaconBlock)
		}

		if blinded {
			return p.CapellaBlinded, nil
		}

		return p.Capella, nil
	case eth2util.DataVersionDeneb:
		if p.Deneb == nil && !blinded {
			p.Deneb = new(eth2deneb.BlockContents)
		}

		if p.DenebBlinded == nil && blinded {
			p.DenebBlinded = new(eth2deneb.BlindedBeaconBlock)
		}

		if blinded {
			return p.DenebBlinded, nil
		}

		return p.Deneb, nil
	case eth2util.DataVersionElectra:
		if p.Electra == nil && !blinded {
			p.Electra = new(eth2electra.BlockContents)
		}

		if p.ElectraBlinded == nil && blinded {
			p.ElectraBlinded = new(eth2electra.BlindedBeaconBlock)
		}

		if blinded {
			return p.ElectraBlinded, nil
		}

		return p.Electra, nil
	case eth2util.DataVersionFulu:
		if p.Fulu == nil && !blinded {
			p.Fulu = new(eth2electra.BlockContents) // Fulu blocks have the same structure as electra blocks.
		}

		if p.FuluBlinded == nil && blinded {
			p.FuluBlinded = new(eth2electra.BlindedBeaconBlock) // Fulu blinded blocks have the same structure as electra blinded blocks.
		}

		if blinded {
			return p.FuluBlinded, nil
		}

		return p.Fulu, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedAttestation ===================

// MarshalSSZ ssz marshals the VersionedAttestation object.
func (a VersionedAttestation) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(a)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedAttestation")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedAttestation object to a target array.
func (a VersionedAttestation) MarshalSSZTo(dst []byte) ([]byte, error) {
	version, err := eth2util.DataVersionFromETH2(a.Version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid version")
	}

	if a.ValidatorIndex == nil {
		return marshalSSZVersionedTo(dst, version, a.sszValFromVersion)
	}

	valIdx := *a.ValidatorIndex

	return marshalSSZVersionedValidatorIdxTo(dst, version, valIdx, a.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshalls the VersionedAttestation object.
func (a *VersionedAttestation) UnmarshalSSZ(b []byte) error {
	version, valIdx, err := unmarshalSSZVersionedValidatorIdx(b, a.sszValFromVersion)
	if err != nil {
		// Previously a bug was introduced where validator index was not marshaled.
		// Ensure backwards compatibility with nodes that have not yet updated to the new fixed version.
		if !errors.Is(err, ssz.ErrOffset) {
			return errors.Wrap(err, "unmarshal VersionedAttestation")
		}

		version, err = unmarshalSSZVersioned(b, a.sszValFromVersion)
		if err != nil {
			return errors.Wrap(err, "unmarshal VersionedAttestation without validator index")
		}
	}

	a.Version = version.ToETH2()
	a.ValidatorIndex = valIdx

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedAttestation object.
func (a VersionedAttestation) SizeSSZ() int {
	version, err := eth2util.DataVersionFromETH2(a.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	val, err := a.sszValFromVersion(version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZValIdxVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedAttestation object for a given version.
func (a *VersionedAttestation) sszValFromVersion(version eth2util.DataVersion) (sszType, error) {
	switch version {
	case eth2util.DataVersionPhase0:
		if a.Phase0 == nil {
			a.Phase0 = new(eth2p0.Attestation)
		}

		return a.Phase0, nil
	case eth2util.DataVersionAltair:
		if a.Altair == nil {
			a.Altair = new(eth2p0.Attestation)
		}

		return a.Altair, nil
	case eth2util.DataVersionBellatrix:
		if a.Bellatrix == nil {
			a.Bellatrix = new(eth2p0.Attestation)
		}

		return a.Bellatrix, nil
	case eth2util.DataVersionCapella:
		if a.Capella == nil {
			a.Capella = new(eth2p0.Attestation)
		}

		return a.Capella, nil
	case eth2util.DataVersionDeneb:
		if a.Deneb == nil {
			a.Deneb = new(eth2p0.Attestation)
		}

		return a.Deneb, nil
	case eth2util.DataVersionElectra:
		if a.Electra == nil {
			a.Electra = new(electra.Attestation)
		}

		return a.Electra, nil
	case eth2util.DataVersionFulu:
		if a.Fulu == nil {
			a.Fulu = new(electra.Attestation)
		}

		return a.Fulu, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedSignedAggregateAndProof ===================

// MarshalSSZ ssz marshals the VersionedSignedAggregateAndProof object.
func (ap VersionedSignedAggregateAndProof) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(ap)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedSignedAggregateAndProof")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedSignedAggregateAndProof object to a target array.
func (ap VersionedSignedAggregateAndProof) MarshalSSZTo(dst []byte) ([]byte, error) {
	version, err := eth2util.DataVersionFromETH2(ap.Version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid version")
	}

	return marshalSSZVersionedTo(dst, version, ap.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshalls the VersionedSignedAggregateAndProof object.
func (ap *VersionedSignedAggregateAndProof) UnmarshalSSZ(b []byte) error {
	version, err := unmarshalSSZVersioned(b, ap.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedAggregateAndProof")
	}

	ap.Version = version.ToETH2()

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedSignedAggregateAndProof object.
func (ap VersionedSignedAggregateAndProof) SizeSSZ() int {
	version, err := eth2util.DataVersionFromETH2(ap.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	val, err := ap.sszValFromVersion(version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedSignedAggregateAndProof object for a given version.
func (ap *VersionedSignedAggregateAndProof) sszValFromVersion(version eth2util.DataVersion) (sszType, error) {
	switch version {
	case eth2util.DataVersionPhase0:
		if ap.Phase0 == nil {
			ap.Phase0 = new(eth2p0.SignedAggregateAndProof)
		}

		return ap.Phase0, nil
	case eth2util.DataVersionAltair:
		if ap.Altair == nil {
			ap.Altair = new(eth2p0.SignedAggregateAndProof)
		}

		return ap.Altair, nil
	case eth2util.DataVersionBellatrix:
		if ap.Bellatrix == nil {
			ap.Bellatrix = new(eth2p0.SignedAggregateAndProof)
		}

		return ap.Bellatrix, nil
	case eth2util.DataVersionCapella:
		if ap.Capella == nil {
			ap.Capella = new(eth2p0.SignedAggregateAndProof)
		}

		return ap.Capella, nil
	case eth2util.DataVersionDeneb:
		if ap.Deneb == nil {
			ap.Deneb = new(eth2p0.SignedAggregateAndProof)
		}

		return ap.Deneb, nil
	case eth2util.DataVersionElectra:
		if ap.Electra == nil {
			ap.Electra = new(electra.SignedAggregateAndProof)
		}

		return ap.Electra, nil
	case eth2util.DataVersionFulu:
		if ap.Fulu == nil {
			ap.Fulu = new(electra.SignedAggregateAndProof)
		}

		return ap.Fulu, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedAggregatedAttestation ===================

// MarshalSSZ ssz marshals the VersionedAggregatedAttestation object.
func (a VersionedAggregatedAttestation) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(a)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedAggregatedAttestation")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedAggregatedAttestation object to a target array.
func (a VersionedAggregatedAttestation) MarshalSSZTo(dst []byte) ([]byte, error) {
	version, err := eth2util.DataVersionFromETH2(a.Version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid version")
	}

	return marshalSSZVersionedTo(dst, version, a.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshalls the VersionedAggregatedAttestation object.
func (a *VersionedAggregatedAttestation) UnmarshalSSZ(b []byte) error {
	version, err := unmarshalSSZVersioned(b, a.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedAggregatedAttestation")
	}

	a.Version = version.ToETH2()

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedAggregatedAttestation object.
func (a VersionedAggregatedAttestation) SizeSSZ() int {
	version, err := eth2util.DataVersionFromETH2(a.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	val, err := a.sszValFromVersion(version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedAggregatedAttestation object for a given version.
func (a *VersionedAggregatedAttestation) sszValFromVersion(version eth2util.DataVersion) (sszType, error) {
	switch version {
	case eth2util.DataVersionPhase0:
		if a.Phase0 == nil {
			a.Phase0 = new(eth2p0.Attestation)
		}

		return a.Phase0, nil
	case eth2util.DataVersionAltair:
		if a.Altair == nil {
			a.Altair = new(eth2p0.Attestation)
		}

		return a.Altair, nil
	case eth2util.DataVersionBellatrix:
		if a.Bellatrix == nil {
			a.Bellatrix = new(eth2p0.Attestation)
		}

		return a.Bellatrix, nil
	case eth2util.DataVersionCapella:
		if a.Capella == nil {
			a.Capella = new(eth2p0.Attestation)
		}

		return a.Capella, nil
	case eth2util.DataVersionDeneb:
		if a.Deneb == nil {
			a.Deneb = new(eth2p0.Attestation)
		}

		return a.Deneb, nil
	case eth2util.DataVersionElectra:
		if a.Electra == nil {
			a.Electra = new(electra.Attestation)
		}

		return a.Electra, nil
	case eth2util.DataVersionFulu:
		if a.Fulu == nil {
			a.Fulu = new(electra.Attestation)
		}

		return a.Fulu, nil
	default:
		return nil, errors.New("invalid version")
	}
}

const (
	// versionedBlindedOffset is the offset of a versioned blinded ssz encoded object.
	versionedBlindedOffset = 8 + 1 + 4 // version (uint64) + blinded (uint8) + offset (uint32)
	// versionedOffset is the offset of a versioned ssz encoded object.
	versionedOffset = 8 + 4 // version (uint64) + offset (uint32)
	// versionedValIdxOffset is the offset of a versioned attestation ssz encoded object.
	versionedValIdxOffset = 8 + 8 + 4 // version (uint64) + validatorIndex (uint64) + offset (uint32)
)

// marshalSSZVersionedBlindedTo marshals a versioned object to a target array.
func marshalSSZVersionedBlindedTo(dst []byte, version eth2util.DataVersion, blinded bool, valFunc func(eth2util.DataVersion, bool) (sszType, error)) ([]byte, error) {
	// Field (0) 'Version'
	dst = ssz.MarshalUint64(dst, version.ToUint64())

	// Field (1) 'Blinded'
	dst = ssz.MarshalBool(dst, blinded)

	// Offset (2) 'Value'
	dst = ssz.WriteOffset(dst, versionedBlindedOffset)

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version, blinded)
	if err != nil {
		return nil, errors.Wrap(err, "sszValFromVersion from version")
	}

	// Field (1) 'Value'
	if dst, err = val.MarshalSSZTo(dst); err != nil {
		return nil, errors.Wrap(err, "marshal sszValFromVersion")
	}

	return dst, nil
}

// marshalSSZVersionedTo marshals a versioned object to a target array.
func marshalSSZVersionedValidatorIdxTo(dst []byte, version eth2util.DataVersion, valIdx eth2p0.ValidatorIndex, valFunc func(eth2util.DataVersion) (sszType, error)) ([]byte, error) {
	// Field (0) 'Version'
	dst = ssz.MarshalUint64(dst, version.ToUint64())

	// Field (1) 'ValidatorIndex'
	dst = ssz.MarshalUint64(dst, uint64(valIdx))

	// Offset (2) 'Value'
	dst = ssz.WriteOffset(dst, versionedValIdxOffset)

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version)
	if err != nil {
		return nil, errors.Wrap(err, "sszValFromVersion from version")
	}

	// Field (2) 'Value'
	if dst, err = val.MarshalSSZTo(dst); err != nil {
		return nil, errors.Wrap(err, "marshal sszValFromVersion")
	}

	return dst, nil
}

// marshalSSZVersionedTo marshals a versioned object to a target array.
func marshalSSZVersionedTo(dst []byte, version eth2util.DataVersion, valFunc func(eth2util.DataVersion) (sszType, error)) ([]byte, error) {
	// Field (0) 'Version'
	dst = ssz.MarshalUint64(dst, version.ToUint64())

	// Offset (1) 'Value'
	dst = ssz.WriteOffset(dst, versionedOffset)

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version)
	if err != nil {
		return nil, errors.Wrap(err, "sszValFromVersion from version")
	}

	// Field (1) 'Value'
	if dst, err = val.MarshalSSZTo(dst); err != nil {
		return nil, errors.Wrap(err, "marshal sszValFromVersion")
	}

	return dst, nil
}

// unmarshalSSZVersionedBlinded unmarshals a versioned object.
func unmarshalSSZVersionedBlinded(buf []byte, valFunc func(eth2util.DataVersion, bool) (sszType, error)) (eth2util.DataVersion, bool, error) {
	if len(buf) < versionedBlindedOffset {
		return "", false, errors.Wrap(ssz.ErrSize, "versioned object too short")
	}

	// Field (0) 'Version'
	version, err := eth2util.DataVersionFromUint64(ssz.UnmarshallUint64(buf[0:8]))
	if err != nil {
		return "", false, errors.Wrap(err, "unmarshal sszValFromVersion version")
	}

	// Field (1) 'Blinded'
	blinded := ssz.UnmarshalBool(buf[8:9])

	// Offset (2) 'Value'
	o1 := ssz.ReadOffset(buf[9:13])
	if versionedBlindedOffset > o1 {
		return "", false, errors.Wrap(ssz.ErrOffset, "sszValFromVersion offset", z.Any("version", version), z.Bool("blinded", blinded))
	}

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version, blinded)
	if err != nil {
		return "", false, errors.Wrap(err, "sszValFromVersion from version", z.Any("version", version), z.Bool("blinded", blinded))
	}

	if err = val.UnmarshalSSZ(buf[o1:]); err != nil {
		return "", false, errors.Wrap(err, "unmarshal sszValFromVersion", z.Any("version", version), z.Bool("blinded", blinded))
	}

	return version, blinded, nil
}

// unmarshalSSZVersionedValidatorIdx unmarshals a versioned attestation object.
func unmarshalSSZVersionedValidatorIdx(buf []byte, valFunc func(eth2util.DataVersion) (sszType, error)) (eth2util.DataVersion, *eth2p0.ValidatorIndex, error) {
	if len(buf) < versionedValIdxOffset {
		return "", nil, errors.Wrap(ssz.ErrSize, "versioned object too short")
	}

	// Field (0) 'Version'
	version, err := eth2util.DataVersionFromUint64(ssz.UnmarshallUint64(buf[0:8]))
	if err != nil {
		return "", nil, errors.Wrap(err, "unmarshal sszValFromVersion version")
	}

	// Field (1) 'ValidatorIndex'
	valIdx := eth2p0.ValidatorIndex(ssz.UnmarshallUint64(buf[8:16]))

	// Offset (2) 'Value'
	o1 := ssz.ReadOffset(buf[16:20])
	if o1 != versionedValIdxOffset {
		return "", nil, errors.Wrap(ssz.ErrOffset, "sszValFromVersion offset", z.Any("version", version))
	}

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version)
	if err != nil {
		return "", nil, errors.Wrap(err, "sszValFromVersion from version", z.Any("version", version))
	}

	if err = val.UnmarshalSSZ(buf[o1:]); err != nil {
		return "", nil, errors.Wrap(err, "unmarshal sszValFromVersion", z.Any("version", version))
	}

	return version, &valIdx, nil
}

// unmarshalSSZVersioned unmarshals a versioned object.
func unmarshalSSZVersioned(buf []byte, valFunc func(eth2util.DataVersion) (sszType, error)) (eth2util.DataVersion, error) {
	if len(buf) < versionedOffset {
		return "", errors.Wrap(ssz.ErrSize, "versioned object too short")
	}

	// Field (0) 'Version'
	version, err := eth2util.DataVersionFromUint64(ssz.UnmarshallUint64(buf[0:8]))
	if err != nil {
		return "", errors.Wrap(err, "unmarshal sszValFromVersion version")
	}

	// Offset (1) 'Value'
	o1 := ssz.ReadOffset(buf[8:12])
	if versionedOffset > o1 {
		return "", errors.Wrap(ssz.ErrOffset, "sszValFromVersion offset", z.Any("version", version))
	}

	// TODO(corver): Add a constant length data version string field, ensure this is backwards compatible.

	val, err := valFunc(version)
	if err != nil {
		return "", errors.Wrap(err, "sszValFromVersion from version", z.Any("version", version))
	}

	if err = val.UnmarshalSSZ(buf[o1:]); err != nil {
		return "", errors.Wrap(err, "unmarshal sszValFromVersion", z.Any("version", version))
	}

	return version, nil
}

// sizeSSZVersionedBlinded returns the ssz encoded size in bytes for a given versioned object.
func sizeSSZVersionedBlinded(value sszType) int {
	return versionedBlindedOffset + value.SizeSSZ()
}

// sizeSSZVersioned returns the ssz encoded size in bytes for a given versioned object.
func sizeSSZVersioned(value sszType) int {
	return versionedOffset + value.SizeSSZ()
}

// sizeSSZValIdxVersioned returns the ssz encoded size in bytes for a given versioned object.
func sizeSSZValIdxVersioned(value sszType) int {
	return versionedValIdxOffset + value.SizeSSZ()
}

// VersionedBlindedSSZValueForT exposes the value method of a type for testing purposes.
func VersionedBlindedSSZValueForT(t *testing.T, value any, version eth2util.DataVersion, blinded bool) sszType {
	t.Helper()

	resp, err := value.(interface {
		sszValFromVersion(version eth2util.DataVersion, blinded bool) (sszType, error)
	}).sszValFromVersion(version, blinded)
	require.NoError(t, err)

	return resp
}

// VersionedBlindedSSZValueForT exposes the value method of a type for testing purposes.
func VersionedSSZValueForT(t *testing.T, value any, version eth2util.DataVersion) sszType {
	t.Helper()

	resp, err := value.(interface {
		sszValFromVersion(version eth2util.DataVersion) (sszType, error)
	}).sszValFromVersion(version)
	require.NoError(t, err)

	return resp
}

func (a AttestationData) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(a)
	if err != nil {
		return nil, errors.Wrap(err, "marshal AttestationData")
	}

	return resp, nil
}

func (a AttestationData) MarshalSSZTo(dst []byte) ([]byte, error) {
	offset := 4 + 4 // 2*offset (uint32)

	// Offset (0) 'AttestationData'
	dst = ssz.WriteOffset(dst, offset)
	offset += a.Data.SizeSSZ()

	// Offset (1) 'AttesterDuty'
	dst = ssz.WriteOffset(dst, offset)

	// Field (0) 'AttestationData'
	dst, err := a.Data.MarshalSSZTo(dst)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attestation data")
	}

	// Field (1) 'AttesterDuty'
	dst, err = attesterDutySSZ(a.Duty).MarshalSSZTo(dst)
	if err != nil {
		return nil, errors.Wrap(err, "marshal attester duty")
	}

	return dst, nil
}

func (a AttestationData) SizeSSZ() int {
	return 4 + 4 + a.Data.SizeSSZ() + attesterDutySSZ(a.Duty).SizeSSZ()
}

func (a *AttestationData) UnmarshalSSZ(buf []byte) error {
	minSize := uint64(4 + 4)

	size := uint64(len(buf))
	if size < minSize {
		return errors.Wrap(ssz.ErrSize, "attestation data too short")
	}

	// Offset (0) 'AttestationData'
	o0 := ssz.ReadOffset(buf[0:4])
	if size < o0 || minSize > o0 {
		return errors.Wrap(ssz.ErrOffset, "attestation data offset")
	}

	// Offset (1) 'AttesterDuty'
	o1 := ssz.ReadOffset(buf[4:8])
	if size < o1 || o0 > o1 {
		return errors.Wrap(ssz.ErrOffset, "attester duty offset")
	}

	// Field (0) 'AttestationData'
	if err := a.Data.UnmarshalSSZ(buf[o0:o1]); err != nil {
		return errors.Wrap(err, "unmarshal attestation data")
	}

	// Field (1) 'AttesterDuty'
	if err := (*attesterDutySSZ)(&a.Duty).UnmarshalSSZ(buf[o1:]); err != nil {
		return errors.Wrap(err, "unmarshal attester duty")
	}

	return nil
}

// attesterDutySSZ is a wrapper around eth2v1.AttesterDuty to implement the sszType interface.
type attesterDutySSZ eth2v1.AttesterDuty

func (a attesterDutySSZ) MarshalSSZTo(dst []byte) ([]byte, error) {
	// Field (0) 'PubKey'
	dst = append(dst, a.PubKey[:]...)

	// Field (1) 'Slot'
	dst = ssz.MarshalUint64(dst, uint64(a.Slot))

	// Field (2) 'ValidatorIndex'
	dst = ssz.MarshalUint64(dst, uint64(a.ValidatorIndex))

	// Field (3) 'CommitteeIndex'
	dst = ssz.MarshalUint64(dst, uint64(a.CommitteeIndex))

	// Field (4) 'CommitteeLength'
	dst = ssz.MarshalUint64(dst, a.CommitteeLength)

	// Field (5) 'CommitteesAtSlot'
	dst = ssz.MarshalUint64(dst, a.CommitteesAtSlot)

	// Field (6) 'ValidatorCommitteeIndex'
	dst = ssz.MarshalUint64(dst, a.ValidatorCommitteeIndex)

	return dst, nil
}

func (attesterDutySSZ) SizeSSZ() int {
	return 48 + 6*8 // Pubkey (48) + 6*uint64s
}

func (a *attesterDutySSZ) UnmarshalSSZ(buf []byte) error {
	if len(buf) < a.SizeSSZ() {
		return errors.Wrap(ssz.ErrSize, "attesterDuty unmarshal")
	}

	offset := 0
	next := 48

	// Field (0) 'PubKey'
	copy(a.PubKey[:], buf[offset:next])

	offset, next = next, next+8

	// Field (1) 'Slot'
	a.Slot = eth2p0.Slot(ssz.UnmarshallUint64(buf[offset:next]))

	offset, next = next, next+8

	// Field (2) 'ValidatorIndex'
	a.ValidatorIndex = eth2p0.ValidatorIndex(ssz.UnmarshallUint64(buf[offset:next]))

	offset, next = next, next+8

	// Field (3) 'CommitteeIndex'
	a.CommitteeIndex = eth2p0.CommitteeIndex(ssz.UnmarshallUint64(buf[offset:next]))

	offset, next = next, next+8

	// Field (4) 'CommitteeLength'
	a.CommitteeLength = ssz.UnmarshallUint64(buf[offset:next])

	offset, next = next, next+8

	// Field (5) 'CommitteesAtSlot'
	a.CommitteesAtSlot = ssz.UnmarshallUint64(buf[offset:next])

	offset, next = next, next+8

	// Field (6) 'ValidatorCommitteeIndex'
	a.ValidatorCommitteeIndex = ssz.UnmarshallUint64(buf[offset:next])

	return nil
}
