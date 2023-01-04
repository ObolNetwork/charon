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

package validatormock

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestGetSubcommittees(t *testing.T) {
	ctx := context.Background()
	bmock, err := beaconmock.New(
		beaconmock.WithSyncCommitteeSize(512),
		beaconmock.WithSyncCommitteeSubnetCount(4),
	)
	require.NoError(t, err)

	duty := &eth2v1.SyncCommitteeDuty{
		PubKey:                        testutil.RandomEth2PubKey(t),
		ValidatorIndex:                0,
		ValidatorSyncCommitteeIndices: []eth2p0.CommitteeIndex{75, 133, 289, 491},
	}

	expected := []eth2p0.CommitteeIndex{0, 1, 2, 3}

	subcommittees, err := getSubcommittees(ctx, bmock, duty)
	require.NoError(t, err)
	require.Equal(t, expected, subcommittees)
}
