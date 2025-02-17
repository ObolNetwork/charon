// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/protonil"
	"github.com/obolnetwork/charon/app/z"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// sszMarshallingEnabled is enabled from v0.17.
var sszMarshallingEnabled = true

// DisableSSZMarshallingForT disables SSZ marshalling for the duration of the test.
func DisableSSZMarshallingForT(t *testing.T) {
	t.Helper()
	sszMarshallingEnabled = false
	t.Cleanup(func() {
		sszMarshallingEnabled = true
	})
}

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
		Slot: duty.GetSlot(),
		Type: DutyType(duty.GetType()),
	}
}

// ParSignedDataFromProto returns the data from a protobuf.
func ParSignedDataFromProto(typ DutyType, data *pbv1.ParSignedData) (_ ParSignedData, oerr error) {
	defer func() {
		// This is to respect the technical possibility of unmarshalling to panic.
		// However, our protobuf generated types do not have custom marshallers that may panic.
		if r := recover(); r != nil {
			rowStr := fmt.Sprintf("%v", r)
			oerr = errors.Wrap(errors.New(rowStr), "panic recovered")
		}
	}()

	if err := protonil.Check(data); err != nil {
		return ParSignedData{}, errors.Wrap(err, "invalid partial signed proto")
	}

	var signedData SignedData
	switch typ {
	case DutyAttester:
		var a Attestation
		err := unmarshal(data.GetData(), &a)
		if err == nil {
			signedData = a
		} else {
			var av VersionedAttestation
			err = unmarshal(data.GetData(), &av)
			if err != nil {
				return ParSignedData{}, errors.Wrap(err, "unmarshal attestation")
			}
			signedData = av
		}
	case DutyProposer:
		var b VersionedSignedProposal
		if err := unmarshal(data.GetData(), &b); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal proposal")
		}
		signedData = b
	case DutyBuilderProposer:
		return ParSignedData{}, ErrDeprecatedDutyBuilderProposer
	case DutyBuilderRegistration:
		var r VersionedSignedValidatorRegistration
		if err := unmarshal(data.GetData(), &r); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal validator (builder) registration")
		}
		signedData = r
	case DutyExit:
		var e SignedVoluntaryExit
		if err := unmarshal(data.GetData(), &e); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal exit")
		}
		signedData = e
	case DutyRandao:
		var s SignedRandao
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signed randao")
		}
		signedData = s
	case DutySignature:
		var s Signature
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signature")
		}
		signedData = s
	case DutyPrepareAggregator:
		var s BeaconCommitteeSelection
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal beacon committee subscription")
		}
		signedData = s
	case DutyAggregator:
		var s SignedAggregateAndProof
		err := unmarshal(data.GetData(), &s)
		if err == nil {
			signedData = s
		} else {
			var sv VersionedSignedAggregateAndProof
			err = unmarshal(data.GetData(), &sv)
			if err != nil {
				return ParSignedData{}, errors.Wrap(err, "unmarshal signed aggregate and proof")
			}
			signedData = sv
		}
	case DutySyncMessage:
		var s SignedSyncMessage
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal signed sync message")
		}
		signedData = s
	case DutyPrepareSyncContribution:
		var s SyncCommitteeSelection
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal sync committee selection")
		}
		signedData = s
	case DutySyncContribution:
		var s SignedSyncContributionAndProof
		if err := unmarshal(data.GetData(), &s); err != nil {
			return ParSignedData{}, errors.Wrap(err, "unmarshal sync contribution and proof")
		}
		signedData = s
	default:
		return ParSignedData{}, errors.New("unsupported duty type")
	}

	return ParSignedData{
		SignedData: signedData,
		ShareIdx:   int(data.GetShareIdx()),
	}, nil
}

// ParSignedDataToProto returns the data as a protobuf.
func ParSignedDataToProto(data ParSignedData) (*pbv1.ParSignedData, error) {
	d, err := marshal(data.SignedData)
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
	if set == nil || len(set.GetSet()) == 0 {
		return nil, errors.New("invalid partial signed data set proto fields", z.Any("set", set))
	}

	var (
		resp = make(ParSignedDataSet)
		err  error
	)
	for pubkey, data := range set.GetSet() {
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
		inner[string(pubkey)], err = marshal(data)
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
	if set == nil || len(set.GetSet()) == 0 {
		return nil, errors.New("invalid unsigned data set fields", z.Any("set", set))
	}

	resp := make(UnsignedDataSet)
	for pubkey, data := range set.GetSet() {
		var err error
		resp[PubKey(pubkey)], err = unmarshalUnsignedData(typ, data)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// marshal marshals the given value into bytes, either as SSZ if supported by the type (and if enabled) or as json.
func marshal(v any) ([]byte, error) {
	// First try SSZ
	if marshaller, ok := v.(ssz.Marshaler); ok && sszMarshallingEnabled {
		b, err := marshaller.MarshalSSZ()
		if err != nil {
			return nil, errors.Wrap(err, "marshal ssz")
		}

		return b, nil
	}

	// Else try json
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errors.Wrap(err, "marshal json")
	}

	return b, nil
}

// unmarshal unmarshals the data into the given value pointer
// It tries to unmarshal as ssz first, then as json.
func unmarshal(data []byte, v any) error {
	// First try ssz
	if unmarshaller, ok := v.(ssz.Unmarshaler); ok {
		if err := unmarshaller.UnmarshalSSZ(data); err == nil {
			return nil
		} else if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
			// No json prefix, so no point attempting json unmarshalling.
			return errors.Wrap(err, "unmarshal ssz")
		}
	}

	// Else try json
	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	return nil
}
