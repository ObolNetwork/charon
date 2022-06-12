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

package core_test

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestDutyProto(t *testing.T) {
	duty1 := core.NewAttesterDuty(99)
	pb1 := core.DutyToProto(duty1)
	duty2 := core.DutyFromProto(pb1)
	pb2 := core.DutyToProto(duty2)
	require.Equal(t, duty1, duty2)
	require.Equal(t, pb1, pb2)
}

func TestParSignedDataProto(t *testing.T) {
	data1 := core.ParSignedData{
		Data:      testutil.RandomBytes32(),
		Signature: testutil.RandomCoreSignature(),
		ShareIdx:  99,
	}
	pb1 := core.ParSignedDataToProto(data1)
	data2 := core.ParSignedDataFromProto(pb1)
	pb2 := core.ParSignedDataToProto(data2)
	require.Equal(t, data1, data2)
	require.Equal(t, pb1, pb2)
}

func TestParSignedDataSetProto(t *testing.T) {
	set1 := core.ParSignedDataSet{
		testutil.RandomCorePubKey(t): core.ParSignedData{
			Data:      testutil.RandomBytes32(),
			Signature: testutil.RandomCoreSignature(),
			ShareIdx:  99,
		},
		testutil.RandomCorePubKey(t): core.ParSignedData{
			Data:      testutil.RandomBytes32(),
			Signature: testutil.RandomCoreSignature(),
			ShareIdx:  123,
		},
	}
	pb1 := core.ParSignedDataSetToProto(set1)
	set2 := core.ParSignedDataSetFromProto(pb1)
	pb2 := core.ParSignedDataSetToProto(set2)
	require.Equal(t, set1, set2)
	require.Equal(t, pb1, pb2)
}

func TestParSignedData2(t *testing.T) {
	for typ, signedData := range randomSignedData(t) {
		t.Run(typ.String(), func(t *testing.T) {
			parSig1 := core.ParSignedData2{
				SignedData: signedData,
				ShareIdx:   rand.Intn(100),
			}

			pb1, err := core.ParSignedData2ToProto(parSig1)
			require.NoError(t, err)
			parSig2, err := core.ParSignedData2FromProto(typ, pb1)
			require.NoError(t, err)
			pb2, err := core.ParSignedData2ToProto(parSig2)
			require.NoError(t, err)
			require.Equal(t, parSig1, parSig2)
			require.Equal(t, pb1, pb2)

			b, err := proto.Marshal(pb1)
			require.NoError(t, err)

			pb3 := new(pbv1.ParSignedData)
			err = proto.Unmarshal(b, pb3)
			require.NoError(t, err)

			require.True(t, proto.Equal(pb1, pb3))
		})
	}
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
	att := core.Attestation{Attestation: *testutil.RandomAttestation()}

	b, err := json.Marshal(att)
	require.NoError(t, err)

	b2, err := att.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, b, b2)

	var a core.SignedData
	a = &core.Attestation{}
	err = json.Unmarshal(b, a)
	require.NoError(t, err)

	require.Equal(t, &att, a)
}

func randomSignedData(t *testing.T) map[core.DutyType]core.SignedData {
	t.Helper()

	return map[core.DutyType]core.SignedData{
		core.DutyAttester: core.Attestation{Attestation: *testutil.RandomAttestation()},
		core.DutyExit:     core.SignedVoluntaryExit{SignedVoluntaryExit: *testutil.RandomExit()},
		core.DutyRandao:   testutil.RandomCoreSignature(),
		core.DutyProposer: core.VersionedSignedBeaconBlock{
			VersionedSignedBeaconBlock: spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   testutil.RandomBellatrixBeaconBlock(t),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
	}
}
