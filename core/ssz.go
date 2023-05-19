// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"testing"

	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

type sszType interface {
	ssz.Marshaler
	ssz.Unmarshaler
}

// MarshalSSZ ssz marshals the VersionedSignedBeaconBlock object.
func (b VersionedSignedBeaconBlock) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(b)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedSignedBeaconBlock")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedSignedBeaconBlock object to a target array.
func (b VersionedSignedBeaconBlock) MarshalSSZTo(buf []byte) ([]byte, error) {
	return marshalSSZVersionedTo(buf, b.Version, b.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshals the VersionedSignedBeaconBlock object.
func (b *VersionedSignedBeaconBlock) UnmarshalSSZ(buf []byte) error {
	version, err := unmarshalSSZVersioned(buf, b.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedBeaconBlock")
	}

	b.Version = version

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedSignedBeaconBlock object.
func (b VersionedSignedBeaconBlock) SizeSSZ() int {
	val, err := b.sszValFromVersion(b.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedSignedBeaconBlock object for a given version.
func (b *VersionedSignedBeaconBlock) sszValFromVersion(version eth2spec.DataVersion) (sszType, error) {
	switch version {
	case eth2spec.DataVersionPhase0:
		if b.Phase0 == nil {
			b.Phase0 = new(eth2p0.SignedBeaconBlock)
		}

		return b.Phase0, nil
	case eth2spec.DataVersionAltair:
		if b.Altair == nil {
			b.Altair = new(altair.SignedBeaconBlock)
		}

		return b.Altair, nil
	case eth2spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			b.Bellatrix = new(bellatrix.SignedBeaconBlock)
		}

		return b.Bellatrix, nil
	case eth2spec.DataVersionCapella:
		if b.Capella == nil {
			b.Capella = new(capella.SignedBeaconBlock)
		}

		return b.Capella, nil
	case eth2spec.DataVersionDeneb:
		if b.Deneb == nil {
			b.Deneb = new(deneb.SignedBeaconBlock)
		}

		return b.Deneb, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedSignedBeaconBlock ===================

// MarshalSSZ ssz marshals the VersionedBeaconBlock object.
func (b VersionedBeaconBlock) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(b)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedBeaconBlock")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedBeaconBlock object to a target array.
func (b VersionedBeaconBlock) MarshalSSZTo(buf []byte) ([]byte, error) {
	return marshalSSZVersionedTo(buf, b.Version, b.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshals the VersionedBeaconBlock object.
func (b *VersionedBeaconBlock) UnmarshalSSZ(buf []byte) error {
	version, err := unmarshalSSZVersioned(buf, b.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedBeaconBlock")
	}

	b.Version = version

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedBeaconBlock object.
func (b VersionedBeaconBlock) SizeSSZ() int {
	val, err := b.sszValFromVersion(b.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedBeaconBlock object for a given version.
func (b *VersionedBeaconBlock) sszValFromVersion(version eth2spec.DataVersion) (sszType, error) {
	switch version {
	case eth2spec.DataVersionPhase0:
		if b.Phase0 == nil {
			b.Phase0 = new(eth2p0.BeaconBlock)
		}

		return b.Phase0, nil
	case eth2spec.DataVersionAltair:
		if b.Altair == nil {
			b.Altair = new(altair.BeaconBlock)
		}

		return b.Altair, nil
	case eth2spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			b.Bellatrix = new(bellatrix.BeaconBlock)
		}

		return b.Bellatrix, nil
	case eth2spec.DataVersionCapella:
		if b.Capella == nil {
			b.Capella = new(capella.BeaconBlock)
		}

		return b.Capella, nil
	case eth2spec.DataVersionDeneb:
		if b.Deneb == nil {
			b.Deneb = new(deneb.BeaconBlock)
		}

		return b.Deneb, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedSignedBlindedBeaconBlock ===================

// MarshalSSZ ssz marshals the VersionedSignedBlindedBeaconBlock object.
func (b VersionedSignedBlindedBeaconBlock) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(b)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedSignedBlindedBeaconBlock")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedSignedBlindedBeaconBlock object to a target array.
func (b VersionedSignedBlindedBeaconBlock) MarshalSSZTo(buf []byte) ([]byte, error) {
	return marshalSSZVersionedTo(buf, b.Version, b.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshals the VersionedSignedBlindedBeaconBlock object.
func (b *VersionedSignedBlindedBeaconBlock) UnmarshalSSZ(buf []byte) error {
	version, err := unmarshalSSZVersioned(buf, b.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedBeaconBlock")
	}

	b.Version = version

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedSignedBlindedBeaconBlock object.
func (b VersionedSignedBlindedBeaconBlock) SizeSSZ() int {
	val, err := b.sszValFromVersion(b.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedSignedBlindedBeaconBlock object for a given version.
func (b *VersionedSignedBlindedBeaconBlock) sszValFromVersion(version eth2spec.DataVersion) (sszType, error) {
	switch version {
	case eth2spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			b.Bellatrix = new(eth2bellatrix.SignedBlindedBeaconBlock)
		}

		return b.Bellatrix, nil
	case eth2spec.DataVersionCapella:
		if b.Capella == nil {
			b.Capella = new(eth2capella.SignedBlindedBeaconBlock)
		}

		return b.Capella, nil

	//	if b.Deneb == nil {
	//		b.Deneb = new(v1deneb.SignedBlindedBeaconBlock)
	//	}
	//	return b.Deneb, nil
	default:
		return nil, errors.New("invalid version")
	}
}

// ================== VersionedBlindedBeaconBlock ===================

// MarshalSSZ ssz marshals the VersionedBlindedBeaconBlock object.
func (b VersionedBlindedBeaconBlock) MarshalSSZ() ([]byte, error) {
	resp, err := ssz.MarshalSSZ(b)
	if err != nil {
		return nil, errors.Wrap(err, "marshal VersionedSignedBlindedBeaconBlock")
	}

	return resp, nil
}

// MarshalSSZTo ssz marshals the VersionedBlindedBeaconBlock object to a target array.
func (b VersionedBlindedBeaconBlock) MarshalSSZTo(buf []byte) ([]byte, error) {
	return marshalSSZVersionedTo(buf, b.Version, b.sszValFromVersion)
}

// UnmarshalSSZ ssz unmarshals the VersionedBlindedBeaconBlock object.
func (b *VersionedBlindedBeaconBlock) UnmarshalSSZ(buf []byte) error {
	version, err := unmarshalSSZVersioned(buf, b.sszValFromVersion)
	if err != nil {
		return errors.Wrap(err, "unmarshal VersionedSignedBeaconBlock")
	}

	b.Version = version

	return nil
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedBlindedBeaconBlock object.
func (b VersionedBlindedBeaconBlock) SizeSSZ() int {
	val, err := b.sszValFromVersion(b.Version)
	if err != nil {
		// SSZMarshaller interface doesn't return an error, so we can't either.
		return 0
	}

	return sizeSSZVersioned(val)
}

// sszValFromVersion returns the internal value of the VersionedBlindedBeaconBlock object for a given version.
func (b *VersionedBlindedBeaconBlock) sszValFromVersion(version eth2spec.DataVersion) (sszType, error) {
	switch version {
	case eth2spec.DataVersionBellatrix:
		if b.Bellatrix == nil {
			b.Bellatrix = new(eth2bellatrix.BlindedBeaconBlock)
		}

		return b.Bellatrix, nil
	case eth2spec.DataVersionCapella:
		if b.Capella == nil {
			b.Capella = new(eth2capella.BlindedBeaconBlock)
		}

		return b.Capella, nil
	//	if b.Deneb == nil {
	//		b.Deneb = new(v1deneb.SignedBlindedBeaconBlock)
	//	}
	//	return b.Deneb, nil
	default:
		return nil, errors.New("invalid version")
	}
}

const versionedOffset = 8 + 4 // version (uint64) + offset (uint32)

func marshalSSZVersionedTo(dst []byte, version eth2spec.DataVersion, valFunc func(eth2spec.DataVersion) (sszType, error)) ([]byte, error) {
	// Field (0) 'Version'
	dst = ssz.MarshalUint64(dst, uint64(version))

	// Offset (1) 'Value'
	dst = ssz.WriteOffset(dst, versionedOffset)

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

func unmarshalSSZVersioned(buf []byte, valFunc func(eth2spec.DataVersion) (sszType, error)) (eth2spec.DataVersion, error) {
	if len(buf) < versionedOffset {
		return 0, errors.Wrap(ssz.ErrSize, "versioned object too short")
	}

	// Field (0) 'Version'
	version := eth2spec.DataVersion(ssz.UnmarshallUint64(buf[0:8]))

	// Offset (1) 'Value'
	o1 := ssz.ReadOffset(buf[8:12])
	if versionedOffset > o1 {
		return 0, errors.Wrap(ssz.ErrOffset, "sszValFromVersion offset", z.Any("version", version))
	}

	val, err := valFunc(version)
	if err != nil {
		return 0, errors.Wrap(err, "sszValFromVersion from version", z.Any("version", version))
	}

	if err = val.UnmarshalSSZ(buf[o1:]); err != nil {
		return 0, errors.Wrap(err, "unmarshal sszValFromVersion", z.Any("version", version))
	}

	return version, nil
}

func sizeSSZVersioned(value sszType) int {
	return versionedOffset + value.SizeSSZ()
}

// VersionedSSZValueForT exposes the sszValFromVersion method of a type for testing purposes.
func VersionedSSZValueForT(t *testing.T, value any, version eth2spec.DataVersion) sszType {
	t.Helper()

	resp, err := value.(interface {
		sszValFromVersion(eth2spec.DataVersion) (sszType, error)
	}).sszValFromVersion(version)
	require.NoError(t, err)

	return resp
}
