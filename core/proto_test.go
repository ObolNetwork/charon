// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"encoding/json"
	"math/rand"
	"testing"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestDutyProto(t *testing.T) {
	duty1 := core.NewAttesterDuty(99)
	pb1 := core.DutyToProto(duty1)
	duty2 := core.DutyFromProto(pb1)
	pb2 := core.DutyToProto(duty2)
	require.Equal(t, duty1, duty2)
	testutil.RequireProtoEqual(t, pb1, pb2)
}

func TestParSignedDataSetProto(t *testing.T) {
	tests := []struct {
		Type core.DutyType
		Data core.SignedData
	}{
		{
			Type: core.DutyAttester,
			Data: testutil.RandomDenebCoreVersionedAttestation(),
		},
		{
			Type: core.DutyAttester,
			Data: testutil.RandomElectraCoreVersionedAttestation(),
		},
		{
			Type: core.DutyExit,
			Data: core.SignedVoluntaryExit{SignedVoluntaryExit: *testutil.RandomExit()},
		},
		{
			Type: core.DutyProposer,
			Data: testutil.RandomBellatrixCoreVersionedSignedProposal(),
		},
		{
			Type: core.DutyProposer,
			Data: testutil.RandomCapellaCoreVersionedSignedProposal(),
		},
		{
			Type: core.DutyProposer,
			Data: testutil.RandomDenebCoreVersionedSignedProposal(),
		},
		{
			Type: core.DutyBuilderRegistration,
			Data: testutil.RandomCoreVersionedSignedValidatorRegistration(t),
		},
		{
			Type: core.DutyPrepareAggregator,
			Data: testutil.RandomCoreBeaconCommitteeSelection(),
		},
		{
			Type: core.DutyAggregator,
			Data: core.VersionedSignedAggregateAndProof{
				VersionedSignedAggregateAndProof: eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionDeneb,
					Deneb: &eth2p0.SignedAggregateAndProof{
						Message:   testutil.RandomAggregateAndProof(),
						Signature: testutil.RandomEth2Signature(),
					},
				},
			},
		},
		{
			Type: core.DutySyncMessage,
			Data: core.NewSignedSyncMessage(testutil.RandomSyncCommitteeMessage()),
		},
		{
			Type: core.DutyPrepareSyncContribution,
			Data: core.NewSyncCommitteeSelection(testutil.RandomSyncCommitteeSelection()),
		},
		{
			Type: core.DutySyncContribution,
			Data: core.NewSignedSyncContributionAndProof(testutil.RandomSignedSyncContributionAndProof()),
		},
	}
	for _, test := range tests {
		t.Run(test.Type.String(), func(t *testing.T) {
			set1 := core.ParSignedDataSet{
				testutil.RandomCorePubKey(t): core.ParSignedData{
					SignedData: test.Data,
					ShareIdx:   rand.Intn(100),
				},
			}
			pb1, err := core.ParSignedDataSetToProto(set1)
			require.NoError(t, err)
			set2, err := core.ParSignedDataSetFromProto(test.Type, pb1)
			require.NoError(t, err)
			pb2, err := core.ParSignedDataSetToProto(set2)
			require.NoError(t, err)
			require.Equal(t, set1, set2)
			testutil.RequireProtoEqual(t, pb1, pb2)

			b, err := proto.Marshal(pb1)
			require.NoError(t, err)

			pb3 := new(pbv1.ParSignedDataSet)
			err = proto.Unmarshal(b, pb3)
			require.NoError(t, err)
			testutil.RequireProtoEqual(t, pb1, pb3)
		})
	}
}

func TestUnsignedDataToProto(t *testing.T) {
	tests := []struct {
		Type core.DutyType
		Data core.UnsignedData
	}{
		{
			Type: core.DutyAttester,
			Data: testutil.RandomCoreAttestationData(t),
		},
		{
			Type: core.DutyProposer,
			Data: testutil.RandomBellatrixCoreVersionedProposal(),
		},
		{
			Type: core.DutyAggregator,
			Data: testutil.RandomDenebCoreVersionedAggregateAttestation(),
		},
		{
			Type: core.DutySyncContribution,
			Data: core.NewSyncContribution(testutil.RandomSyncCommitteeContribution()),
		},
	}

	for _, test := range tests {
		t.Run(test.Type.String(), func(t *testing.T) {
			set1 := core.UnsignedDataSet{
				testutil.RandomCorePubKey(t): test.Data,
			}

			pb1, err := core.UnsignedDataSetToProto(set1)
			require.NoError(t, err)
			set2, err := core.UnsignedDataSetFromProto(test.Type, pb1)
			require.NoError(t, err)
			pb2, err := core.UnsignedDataSetToProto(set2)
			require.NoError(t, err)
			require.Equal(t, set1, set2)
			testutil.RequireProtoEqual(t, pb1, pb2)

			b, err := proto.Marshal(pb1)
			require.NoError(t, err)

			pb3 := new(pbv1.UnsignedDataSet)
			err = proto.Unmarshal(b, pb3)
			require.NoError(t, err)
			testutil.RequireProtoEqual(t, pb1, pb3)
		})
	}
}

func TestParSignedData(t *testing.T) {
	for typ, signedData := range randomSignedData(t) {
		t.Run(typ.String(), func(t *testing.T) {
			parSig1 := core.ParSignedData{
				SignedData: signedData,
				ShareIdx:   rand.Intn(100),
			}

			pb1, err := core.ParSignedDataToProto(parSig1)
			require.NoError(t, err)
			parSig2, err := core.ParSignedDataFromProto(typ, pb1)
			require.NoError(t, err)
			pb2, err := core.ParSignedDataToProto(parSig2)
			require.NoError(t, err)
			require.Equal(t, parSig1, parSig2)
			testutil.RequireProtoEqual(t, pb1, pb2)

			b, err := proto.Marshal(pb1)
			require.NoError(t, err)

			pb3 := new(pbv1.ParSignedData)
			err = proto.Unmarshal(b, pb3)
			require.NoError(t, err)
			testutil.RequireProtoEqual(t, pb1, pb3)
		})
	}
}

func TestParSignedDataFromProtoErrors(t *testing.T) {
	parSig1 := core.ParSignedData{
		SignedData: core.SyncCommitteeSelection{*testutil.RandomSyncCommitteeSelection()},
		ShareIdx:   rand.Intn(100),
	}

	// We need valid protobuf message to test this
	pb1, err := core.ParSignedDataToProto(parSig1)
	require.NoError(t, err)

	_, err = core.ParSignedDataFromProto(core.DutyUnknown, pb1)
	require.ErrorContains(t, err, "unsupported duty type")

	_, err = core.ParSignedDataFromProto(core.DutyProposer, pb1)
	require.ErrorContains(t, err, "unknown version")

	_, err = core.ParSignedDataFromProto(core.DutyBuilderProposer, pb1)
	require.ErrorIs(t, err, core.ErrDeprecatedDutyBuilderProposer)
}

func TestSetSignature(t *testing.T) {
	for typ, signedData := range randomSignedData(t) {
		t.Run(typ.String(), func(t *testing.T) {
			signedData2, err := signedData.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)
			require.NotEqual(t, signedData.Signature(), signedData2.Signature()) // Asset original not modified
		})
	}
}

func TestMarshalAttestation(t *testing.T) {
	att := testutil.RandomDenebCoreVersionedAttestation()

	b, err := json.Marshal(att)
	require.NoError(t, err)

	b2, err := att.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, b, b2)

	a := new(core.VersionedAttestation)
	err = json.Unmarshal(b, a)
	require.NoError(t, err)

	require.Equal(t, &att, a)
}

func randomSignedData(t *testing.T) map[core.DutyType]core.SignedData {
	t.Helper()

	return map[core.DutyType]core.SignedData{
		core.DutyAttester:                testutil.RandomDenebCoreVersionedAttestation(),
		core.DutyExit:                    core.NewSignedVoluntaryExit(testutil.RandomExit()),
		core.DutyRandao:                  core.SignedRandao{SignedEpoch: eth2util.SignedEpoch{Epoch: testutil.RandomEpoch(), Signature: testutil.RandomEth2Signature()}},
		core.DutyProposer:                testutil.RandomBellatrixCoreVersionedSignedProposal(),
		core.DutyPrepareAggregator:       testutil.RandomCoreBeaconCommitteeSelection(),
		core.DutyAggregator:              core.NewVersionedSignedAggregateAndProof(testutil.RandomDenebVersionedSignedAggregateAndProof()),
		core.DutyPrepareSyncContribution: core.NewSyncCommitteeSelection(testutil.RandomSyncCommitteeSelection()),
		core.DutySyncContribution:        core.NewSignedSyncContributionAndProof(testutil.RandomSignedSyncContributionAndProof()),
	}
}

func TestNilPointerChecks(t *testing.T) {
	_, err := core.ParSignedDataFromProto(core.DutyAttester, nil)
	require.ErrorContains(t, err, "invalid partial signed proto: nil protobuf message")

	_, err = core.ParSignedDataSetFromProto(core.DutyAttester, nil)
	require.ErrorContains(t, err, "invalid partial signed data set proto fields")

	_, err = core.ParSignedDataSetFromProto(core.DutyAttester, new(pbv1.ParSignedDataSet))
	require.ErrorContains(t, err, "invalid partial signed data set proto fields")

	_, err = core.UnsignedDataSetFromProto(core.DutyAttester, nil)
	require.ErrorContains(t, err, "invalid unsigned data set fields")

	_, err = core.UnsignedDataSetFromProto(core.DutyAttester, new(pbv1.UnsignedDataSet))
	require.ErrorContains(t, err, "invalid unsigned data set fields")
}
