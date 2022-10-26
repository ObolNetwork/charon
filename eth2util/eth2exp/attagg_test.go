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

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestIsAttAggregator(t *testing.T) {
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
		isAgg, err := eth2exp.IsAttAggregator(ctx, bmock, commLen, tblsconv.SigToETH2(blsSig))
		require.NoError(t, err)
		require.True(t, isAgg)
	})

	t.Run("not an aggregator", func(t *testing.T) {
		// https://github.com/prysmaticlabs/prysm/blob/fc509cc220a82efd555704d41aa362903a06ab9e/beacon-chain/core/helpers/attestation_test.go#L39
		commLen := uint64(64)
		isAgg, err := eth2exp.IsAttAggregator(ctx, bmock, commLen, tblsconv.SigToETH2(blsSig))
		require.NoError(t, err)
		require.False(t, isAgg)
	})
}

func TestIsSyncCommAggregator(t *testing.T) {
	const (
		syncCommSize = 64
		nonAggSig    = "4837cabd917ad39f937e0b45afb6d5654f5742d118e4b98092107841e5cf44fc8601e3ce82d350eb0551ba844e4410f880a603dcc056fb46847a2a0568c4ed30f172ff57f591726c187e8ac228ab0f5651562048be9f60cfcefb8fac355369e5"
	)

	ctx := context.Background()

	t.Run("aggregator", func(t *testing.T) {
		bmock, err := beaconmock.New(
			beaconmock.WithSyncCommitteeSize(syncCommSize),
		)
		require.NoError(t, err)

		sig := testutil.RandomEth2Signature()
		ok, err := eth2exp.IsSyncCommAggregator(ctx, bmock, sig)
		require.NoError(t, err)
		require.True(t, ok) // Since modulo is always 1 (64 / 4 / 16 = 1).
	})

	t.Run("not an aggregator", func(t *testing.T) {
		bmock, err := beaconmock.New()
		require.NoError(t, err)

		sig, err := hex.DecodeString(nonAggSig)
		require.NoError(t, err)

		var resp eth2p0.BLSSignature
		copy(resp[:], sig)

		ok, err := eth2exp.IsSyncCommAggregator(ctx, bmock, resp)
		require.NoError(t, err)
		require.False(t, ok)
	})
}
