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

package eth2exp_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestIsAggregator(t *testing.T) {
	ctx := context.Background()

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// https://github.com/prysmaticlabs/prysm/blob/8627fe72e80009ae162430140bcfff6f209d7a32/beacon-chain/core/helpers/attestation_test.go#L28
	sig, err := hex.DecodeString("8776a37d6802c4797d113169c5fcfda50e68a32058eb6356a6f00d06d7da64c841a00c7c38b9b94a204751eca53707bd03523ce4797827d9bacff116a6e776a20bbccff4b683bf5201b610797ed0502557a58a65c8395f8a1649b976c3112d15")
	require.NoError(t, err)
	blsSig, err := tblsconv.SigFromBytes(sig)
	require.NoError(t, err)

	t.Run("aggregator", func(t *testing.T) {
		// https://github.com/prysmaticlabs/prysm/blob/8627fe72e80009ae162430140bcfff6f209d7a32/beacon-chain/core/helpers/attestation_test.go#L26
		commLen := uint64(3)
		isAgg, err := eth2exp.IsAggregator(ctx, bmock, commLen, tblsconv.SigToETH2(blsSig))
		require.NoError(t, err)
		require.True(t, isAgg)
	})

	t.Run("not an aggregator", func(t *testing.T) {
		// https://github.com/prysmaticlabs/prysm/blob/fc509cc220a82efd555704d41aa362903a06ab9e/beacon-chain/core/helpers/attestation_test.go#L39
		commLen := uint64(64)
		isAgg, err := eth2exp.IsAggregator(ctx, bmock, commLen, tblsconv.SigToETH2(blsSig))
		require.NoError(t, err)
		require.False(t, isAgg)
	})
}
