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
	"testing"

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

func TestParSignedDataSetProto(t *testing.T) {
	tests := []struct {
		Type core.DutyType
		Set  core.ParSignedDataSet
	}{
		{
			Type: core.DutyAttester,
			Set: core.ParSignedDataSet{
				testutil.RandomCorePubKey(t): core.NewAttestation(testutil.RandomAttestation(), 998),
				testutil.RandomCorePubKey(t): core.NewAttestation(testutil.RandomAttestation(), 999),
			},
		},
		{
			Type: core.DutySignature,
			Set: core.ParSignedDataSet{
				testutil.RandomCorePubKey(t): core.NewParSig(testutil.RandomEth2Signature(), 998),
				testutil.RandomCorePubKey(t): core.NewParSig(testutil.RandomEth2Signature(), 999),
			},
		},
		{
			Type: core.DutyExit,
			Set: core.ParSignedDataSet{
				testutil.RandomCorePubKey(t): core.NewSignedExit(testutil.RandomExit(), 998),
				testutil.RandomCorePubKey(t): core.NewSignedExit(testutil.RandomExit(), 998),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Type.String(), func(t *testing.T) {
			pb1, err := core.ParSignedDataSetToProto(test.Set)
			require.NoError(t, err)
			set2, err := core.ParSignedDataSetFromProto(test.Type, pb1)
			require.NoError(t, err)
			pb2, err := core.ParSignedDataSetToProto(set2)
			require.NoError(t, err)
			require.Equal(t, test.Set, set2)
			require.Equal(t, pb1, pb2)

			b, err := proto.Marshal(pb1)
			require.NoError(t, err)

			pb3 := new(pbv1.ParSignedDataSet)
			err = proto.Unmarshal(b, pb3)
			require.NoError(t, err)

			require.True(t, proto.Equal(pb1, pb3))
		})
	}
}
