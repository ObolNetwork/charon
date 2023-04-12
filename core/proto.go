// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"encoding/json"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
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

// ParSignedDataFromProto returns the data from a protobuf.
func ParSignedDataFromProto(typ DutyType, data *pbv1.ParSignedData) (ParSignedData, error) {
	// TODO(corver): This can panic due to json unmarshalling unexpected data.
	//  For now, it is a good way to catch compatibility issues. But we should
	//  recover panics and return an error before launching mainnet.

	if data == nil {
		return ParSignedData{}, errors.New("partial signed data proto cannot be nil")
	}

	var signedData SignedData
	switch typ {
	case DutyAttester:
		var a Attestation
		if err := json.Unmarshal(data.Data, &a); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal attestation")
		}
		signedData = a
	case DutyProposer:
		var b VersionedSignedBeaconBlock
		if err := json.Unmarshal(data.Data, &b); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal block")
		}
		signedData = b
	case DutyBuilderProposer:
		var b VersionedSignedBlindedBeaconBlock
		if err := json.Unmarshal(data.Data, &b); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal blinded block")
		}
		signedData = b
	case DutyBuilderRegistration:
		var r VersionedSignedValidatorRegistration
		if err := json.Unmarshal(data.Data, &r); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal validator (builder) registration")
		}
		signedData = r
	case DutyExit:
		var e SignedVoluntaryExit
		if err := json.Unmarshal(data.Data, &e); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal exit")
		}
		signedData = e
	case DutyRandao:
		var s SignedRandao
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signed randao")
		}
		signedData = s
	case DutySignature:
		var s Signature
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signature")
		}
		signedData = s
	case DutyPrepareAggregator:
		var s BeaconCommitteeSelection
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal beacon committee subscription")
		}
		signedData = s
	case DutyAggregator:
		var s SignedAggregateAndProof
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signed aggregate and proof")
		}
		signedData = s
	case DutySyncMessage:
		var s SignedSyncMessage
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signed sync message")
		}
		signedData = s
	case DutyPrepareSyncContribution:
		var s SyncCommitteeSelection
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal sync committee selection")
		}
		signedData = s
	case DutySyncContribution:
		var s SignedSyncContributionAndProof
		if err := json.Unmarshal(data.Data, &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal sync contribution and proof")
		}
		signedData = s
	default:
		return ParSignedData{}, errors.New("unsupported duty type")
	}

	return ParSignedData{
		SignedData: signedData,
		ShareIdx:   int(data.ShareIdx),
	}, nil
}

// ParSignedDataToProto returns the data as a protobuf.
func ParSignedDataToProto(data ParSignedData) (*pbv1.ParSignedData, error) {
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
	if set == nil || len(set.Set) == 0 {
		return nil, errors.New("invalid partial signed data set proto fields", z.Any("set", set))
	}

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
func UnsignedDataSetToProto(set UnsignedDataSet) (*pbv1.UnsignedDataSet, error) {
	inner := make(map[string][]byte)
	for pubkey, data := range set {
		var err error
		inner[string(pubkey)], err = data.MarshalJSON()
		if err != nil {
			return nil, err
		}
	}

	return &pbv1.UnsignedDataSet{
		Set: inner,
	}, nil
}

// UnsignedDataSetFromProto returns the set from a protobuf.
func UnsignedDataSetFromProto(typ DutyType, set *pbv1.UnsignedDataSet) (UnsignedDataSet, error) {
	if set == nil || len(set.Set) == 0 {
		return nil, errors.New("invalid unsigned data set fields", z.Any("set", set))
	}

	resp := make(UnsignedDataSet)
	for pubkey, data := range set.Set {
		var err error
		resp[PubKey(pubkey)], err = UnmarshalUnsignedData(typ, data)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}
