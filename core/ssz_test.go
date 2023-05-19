// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

// TestSSZ tests SSZ marshalling and unmarshalling.
func TestSSZ(t *testing.T) {
	tests := []struct {
		zero func() any
	}{
		{zero: func() any { return new(core.VersionedSignedBeaconBlock) }},
		{zero: func() any { return new(core.Attestation) }},
		{zero: func() any { return new(core.VersionedSignedBlindedBeaconBlock) }},
		{zero: func() any { return new(core.SignedAggregateAndProof) }},
		{zero: func() any { return new(core.SignedSyncMessage) }},
		{zero: func() any { return new(core.SyncContributionAndProof) }},
		{zero: func() any { return new(core.SignedSyncContributionAndProof) }},
		{zero: func() any { return new(core.AggregatedAttestation) }},
		{zero: func() any { return new(core.VersionedBeaconBlock) }},
		{zero: func() any { return new(core.VersionedBlindedBeaconBlock) }},
		{zero: func() any { return new(core.SyncContribution) }},
	}

	f := testutil.NewEth2Fuzzer(t)

	for _, test := range tests {
		t.Run(fmt.Sprintf("%T", test.zero()), func(t *testing.T) {
			val1, val2 := test.zero(), test.zero()

			f.Fuzz(val1)

			marshaller, ok := val1.(ssz.Marshaler)
			require.True(t, ok)

			b, err := marshaller.MarshalSSZ()
			testutil.RequireNoError(t, err)

			unmarshaller, ok := val2.(ssz.Unmarshaler)
			require.True(t, ok)

			err = unmarshaller.UnmarshalSSZ(b)
			testutil.RequireNoError(t, err)

			require.Equal(t, val1, val2)
		})
	}
}

func TestMarshalUnsignedProto(t *testing.T) {
	tests := []struct {
		unsignedPtr func() any // Need any pointer to avoid wrapping in interface which doesnt' support fuzzing.
		dutyType    core.DutyType
	}{
		{
			dutyType:    core.DutyAttester,
			unsignedPtr: func() any { return new(core.AttestationData) },
		},
		{
			dutyType:    core.DutyAggregator,
			unsignedPtr: func() any { return new(core.AggregatedAttestation) },
		},
		{
			dutyType:    core.DutyProposer,
			unsignedPtr: func() any { return new(core.VersionedBeaconBlock) },
		},
		{
			dutyType:    core.DutyBuilderProposer,
			unsignedPtr: func() any { return new(core.VersionedBlindedBeaconBlock) },
		},
		{
			dutyType:    core.DutySyncContribution,
			unsignedPtr: func() any { return new(core.SyncContribution) },
		},
	}

	f := testutil.NewEth2Fuzzer(t)
	for _, enabledSSZ := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%T_%v", test.unsignedPtr(), enabledSSZ), func(t *testing.T) {
				if enabledSSZ {
					core.EnabledSSZMarshallingForT(t)
				}

				unsignedPtr := test.unsignedPtr()
				f.Fuzz(unsignedPtr)

				// Dereference the pointer to get the unsigned data.
				unsigned := reflect.ValueOf(unsignedPtr).Elem().Interface().(core.UnsignedData)

				set := core.UnsignedDataSet{
					testutil.RandomCorePubKey(t): unsigned,
				}

				pb, err := core.UnsignedDataSetToProto(set)
				require.NoError(t, err)

				b, err := proto.Marshal(pb)
				require.NoError(t, err)
				t.Log(len(b))

				set2, err := core.UnsignedDataSetFromProto(test.dutyType, pb)
				require.NoError(t, err)

				require.Equal(t, set, set2)
			})
		}
	}
}

func TestMarshalParSignedProto(t *testing.T) {
	tests := []struct {
		signedPtr func() any // Need any pointer to avoid wrapping in interface which doesnt' support fuzzing.
		dutyType  core.DutyType
	}{
		{
			dutyType:  core.DutyAttester,
			signedPtr: func() any { return new(core.Attestation) },
		},
		{
			dutyType:  core.DutyAggregator,
			signedPtr: func() any { return new(core.SignedAggregateAndProof) },
		},
		{
			dutyType:  core.DutyProposer,
			signedPtr: func() any { return new(core.VersionedSignedBeaconBlock) },
		},
		{
			dutyType:  core.DutyBuilderProposer,
			signedPtr: func() any { return new(core.VersionedSignedBlindedBeaconBlock) },
		},
		{
			dutyType:  core.DutySyncContribution,
			signedPtr: func() any { return new(core.SignedSyncContributionAndProof) },
		},
	}

	f := testutil.NewEth2Fuzzer(t)
	for _, enabledSSZ := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%T_%v", test.signedPtr(), enabledSSZ), func(t *testing.T) {
				if enabledSSZ {
					core.EnabledSSZMarshallingForT(t)
				}

				signedPtr := test.signedPtr()
				f.Fuzz(signedPtr)

				// Dereference the pointer to get the signed data.
				signed := reflect.ValueOf(signedPtr).Elem().Interface().(core.SignedData)

				set := core.ParSignedDataSet{
					testutil.RandomCorePubKey(t): core.ParSignedData{
						SignedData: signed,
						ShareIdx:   rand.Intn(10),
					},
				}

				pb, err := core.ParSignedDataSetToProto(set)
				require.NoError(t, err)

				b, err := proto.Marshal(pb)
				require.NoError(t, err)
				t.Log(len(b))

				set2, err := core.ParSignedDataSetFromProto(test.dutyType, pb)
				require.NoError(t, err)

				require.Equal(t, set, set2)
			})
		}
	}
}
