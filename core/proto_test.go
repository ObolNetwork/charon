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

	"github.com/obolnetwork/charon/core"
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

func TestShareSignedDataProto(t *testing.T) {
	data1 := core.ShareSignedData{
		Data:      testutil.RandomBytes32(),
		Signature: testutil.RandomCoreSignature(),
		ShareIdx:  99,
	}
	pb1 := core.ShareSignedDataToProto(data1)
	data2 := core.ShareSignedDataFromProto(pb1)
	pb2 := core.ShareSignedDataToProto(data2)
	require.Equal(t, data1, data2)
	require.Equal(t, pb1, pb2)
}

func TestShareSignedDataSetProto(t *testing.T) {
	set1 := core.ShareSignedDataSet{
		testutil.RandomCorePubKey(t): core.ShareSignedData{
			Data:      testutil.RandomBytes32(),
			Signature: testutil.RandomCoreSignature(),
			ShareIdx:  99,
		},
		testutil.RandomCorePubKey(t): core.ShareSignedData{
			Data:      testutil.RandomBytes32(),
			Signature: testutil.RandomCoreSignature(),
			ShareIdx:  123,
		},
	}
	pb1 := core.ShareSignedDataSetToProto(set1)
	set2 := core.ShareSignedDataSetFromProto(pb1)
	pb2 := core.ShareSignedDataSetToProto(set2)
	require.Equal(t, set1, set2)
	require.Equal(t, pb1, pb2)
}
