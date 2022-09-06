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
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
)

func TestCloneUnsignedData(t *testing.T) {
	tests := []struct {
		name string
		data core.UnsignedData
	}{
		{
			name: "versioned beacon block",
			data: testutil.RandomCoreVersionBeaconBlock(t),
		},
		{
			name: "versioned blinded beacon block",
			data: testutil.RandomCoreVersionBlindedBeaconBlock(t),
		},
		{
			name: "beacon committee subscription response",
			data: core.BeaconCommitteeSubscriptionResponse{
				BeaconCommitteeSubscriptionResponse: eth2exp.BeaconCommitteeSubscriptionResponse{
					ValidatorIndex: testutil.RandomVIdx(),
					IsAggregator:   false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone, err := test.data.Clone()
			require.NoError(t, err)
			require.True(t, reflect.DeepEqual(test.data, clone))
		})
	}
}
