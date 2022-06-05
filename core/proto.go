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

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// DutyToProto returns the duty as a protobuf.
func DutyToProto(duty Duty) *pbv1.Duty {
	return &pbv1.Duty{
		Slot: duty.Slot,
		Type: int32(duty.Type),
	}
}

// DutyFromProto returns the duty from a protobuf.
func DutyFromProto(duty *pbv1.Duty) Duty {
	return Duty{
		Slot: duty.Slot,
		Type: DutyType(duty.Type),
	}
}

// ParSignedDataToProto returns the data as a protobuf.
func ParSignedDataToProto(data ParSignedData) (*pbv1.ParSignedData, error) {
	d, err := data.MarshalData()
	if err != nil {
		return nil, errors.Wrap(err, "marshal parsig data")
	}

	return &pbv1.ParSignedData{
		Data:      d,
		Signature: data.Signature(),
		ShareIdx:  int32(data.ShareIdx()),
	}, nil
}

// ParSignedDataFromProto returns the data from a protobuf.
func ParSignedDataFromProto(typ DutyType, data *pbv1.ParSignedData) (ParSignedData, error) {
	switch typ {
	case DutyAttester:
		var a eth2p0.Attestation
		if err := json.Unmarshal(data.Data, &a); err != nil {
			return nil, errors.Wrap(err, "unmarshal attestation")
		}

		return NewAttestation(&a, int(data.ShareIdx)), nil
	case DutyProposer:
		b, err := UnmarshalVersionedSignedBeaconBlock(data.Data)
		if err != nil {
			return nil, err
		}

		return NewVersionedSignedBeaconBlock(b, int(data.ShareIdx))
	case DutyExit:
		var a eth2p0.SignedVoluntaryExit
		if err := json.Unmarshal(data.Data, &a); err != nil {
			return nil, errors.Wrap(err, "unmarshal attestation")
		}

		return NewSignedExit(&a, int(data.ShareIdx)), nil
	case DutySignature, DutyRandao:
		return ParSig{
			BLSSignature: Signature(data.Signature).ToETH2(),
			shareIdx:     int(data.ShareIdx),
		}, nil
	default:
		return nil, errors.New("unsupported duty type")
	}
}

// ParSignedDataSetToProto returns the set as a protobuf.
func ParSignedDataSetToProto(set ParSignedDataSet) (*pbv1.ParSignedDataSet, error) {
	inner := make(map[string]*pbv1.ParSignedData)
	for pubkey, data := range set {
		pb, err := ParSignedDataToProto(data)
		if err != nil {
			return nil, err
		}
		inner[string(pubkey)] = pb
	}

	return &pbv1.ParSignedDataSet{
		Set: inner,
	}, nil
}

// ParSignedDataSetFromProto returns the set from a protobuf.
func ParSignedDataSetFromProto(typ DutyType, set *pbv1.ParSignedDataSet) (ParSignedDataSet, error) {
	var (
		resp = make(ParSignedDataSet)
		err  error
	)
	for pubkey, data := range set.Set {
		resp[PubKey(pubkey)], err = ParSignedDataFromProto(typ, data)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// UnsignedDataSetToProto returns the set as a protobuf.
func UnsignedDataSetToProto(set UnsignedDataSet) *pbv1.UnsignedDataSet {
	inner := make(map[string][]byte)
	for pubkey, data := range set {
		inner[string(pubkey)] = data
	}

	return &pbv1.UnsignedDataSet{
		Set: inner,
	}
}

// UnsignedDataSetFromProto returns the set from a protobuf.
func UnsignedDataSetFromProto(set *pbv1.UnsignedDataSet) UnsignedDataSet {
	resp := make(UnsignedDataSet)
	for pubkey, data := range set.Set {
		resp[PubKey(pubkey)] = data
	}

	return resp
}

func UnmarshalVersionedSignedBeaconBlock(b []byte) (*spec.VersionedSignedBeaconBlock, error) {
	bellatrixBlock := new(bellatrix.SignedBeaconBlock)
	err := bellatrixBlock.UnmarshalJSON(b)
	if err == nil {
		return &spec.VersionedSignedBeaconBlock{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: bellatrixBlock,
		}, nil
	}

	altairBlock := new(altair.SignedBeaconBlock)
	err = altairBlock.UnmarshalJSON(b)
	if err == nil {
		return &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionAltair,
			Altair:  altairBlock,
		}, nil
	}

	phase0Block := new(eth2p0.SignedBeaconBlock)
	err = phase0Block.UnmarshalJSON(b)
	if err == nil {
		return &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionPhase0,
			Phase0:  phase0Block,
		}, nil
	}

	return nil, errors.New("invalid block version")
}
