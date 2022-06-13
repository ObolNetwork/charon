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

// ParSignedData2ToProto returns the data as a protobuf.
func ParSignedData2ToProto(data ParSignedData2) (*pbv1.ParSignedData, error) {
	d, err := data.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "marshal share signed data")
	}

	return &pbv1.ParSignedData{
		Data:      d,
		Signature: data.Signature(),
		ShareIdx:  int32(data.ShareIdx),
	}, nil
}

// ParSignedData2FromProto returns the data from a protobuf.
func ParSignedData2FromProto(typ DutyType, data *pbv1.ParSignedData) (ParSignedData2, error) {
	var signedData SignedData
	switch typ {
	case DutyAttester:
		var a Attestation
		if err := json.Unmarshal(data.Data, &a); err != nil {
			return ParSignedData2{}, errors.Wrap(err, "unmarshal attestation")
		}
		signedData = a
	case DutyProposer:
		var b VersionedSignedBeaconBlock
		if err := json.Unmarshal(data.Data, &b); err != nil {
			return ParSignedData2{}, errors.Wrap(err, "unmarshal block")
		}
		signedData = b
	case DutyExit:
		var e SignedVoluntaryExit
		if err := json.Unmarshal(data.Data, &e); err != nil {
			return ParSignedData2{}, errors.Wrap(err, "unmarshal exit")
		}
		signedData = e
	case DutyRandao:
		var s Signature
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData2{}, errors.Wrap(err, "unmarshal signature")
		}
		signedData = s
	default:
		return ParSignedData2{}, errors.New("unsupported duty type")
	}

	return ParSignedData2{
		SignedData: signedData,
		ShareIdx:   int(data.ShareIdx),
	}, nil
}

// ParSignedDataToProto returns the data as a protobuf.
func ParSignedDataToProto(data ParSignedData) *pbv1.ParSignedData {
	return &pbv1.ParSignedData{
		Data:      data.Data,
		Signature: data.Signature,
		ShareIdx:  int32(data.ShareIdx),
	}
}

// ParSignedDataFromProto returns the data from a protobuf.
func ParSignedDataFromProto(data *pbv1.ParSignedData) ParSignedData {
	return ParSignedData{
		Data:      data.Data,
		Signature: data.Signature,
		ShareIdx:  int(data.ShareIdx),
	}
}

// ParSignedDataSetToProto returns the set as a protobuf.
func ParSignedDataSetToProto(set ParSignedDataSet) *pbv1.ParSignedDataSet {
	inner := make(map[string]*pbv1.ParSignedData)
	for pubkey, data := range set {
		inner[string(pubkey)] = ParSignedDataToProto(data)
	}

	return &pbv1.ParSignedDataSet{
		Set: inner,
	}
}

// ParSignedDataSetFromProto returns the set from a protobuf.
func ParSignedDataSetFromProto(set *pbv1.ParSignedDataSet) ParSignedDataSet {
	resp := make(ParSignedDataSet)
	for pubkey, data := range set.Set {
		resp[PubKey(pubkey)] = ParSignedDataFromProto(data)
	}

	return resp
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
