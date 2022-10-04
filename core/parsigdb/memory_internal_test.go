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

package parsigdb

import (
	"reflect"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestShouldOutput(t *testing.T) {
	const (
		n  = 4
		th = 3
	)

	duty := core.NewSyncMessageDuty(123)
	root1 := testutil.RandomRoot()
	root2 := testutil.RandomRoot()

	var (
		data []core.ParSignedData
		msgs []*altair.SyncCommitteeMessage
	)

	for i := 0; i < n-1; i++ {
		msg := testutil.RandomSyncCommitteeMessage()
		msg.BeaconBlockRoot = root1
		msgs = append(msgs, msg)
		data = append(data, core.NewPartialSignedSyncMessage(msg, i))
	}

	out, ok, err := calculateOutput(duty, data, th)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, reflect.DeepEqual(out, data[:n-1]))

	for i := 0; i < n/2; i++ {
		msgs[i].BeaconBlockRoot = root2
		data[i] = core.NewPartialSignedSyncMessage(msgs[i], i)
	}

	_, ok, err = calculateOutput(duty, data, th)
	require.NoError(t, err)
	require.False(t, ok)
}
