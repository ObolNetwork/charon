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
	"math/rand"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestCalculateCommitteeSubscriptionResponse(t *testing.T) {
	ctx := context.Background()

	const (
		commIdx = 1
		slot    = 1
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	_, secret, err := tbls.KeygenWithSeed(rand.New(rand.NewSource(1)))
	require.NoError(t, err)

	sigRoot, err := eth2util.SlotHashRoot(slot)
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)
	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainSelectionProof, epoch, sigRoot)
	require.NoError(t, err)

	sig, _ := tbls.Sign(secret, sigData[:])
	blssig := tblsconv.SigToETH2(sig)

	t.Run("is aggregator", func(t *testing.T) {
		commLen := 43
		var vals []eth2p0.ValidatorIndex
		for idx := 1; idx <= commLen; idx++ {
			vals = append(vals, eth2p0.ValidatorIndex(idx))
		}
		comms := []*eth2v1.BeaconCommittee{
			{
				Slot:       slot,
				Index:      commIdx,
				Validators: vals,
			},
		}

		bmock.BeaconCommitteesAtEpochFunc = func(_ context.Context, _ string, _ eth2p0.Epoch) ([]*eth2v1.BeaconCommittee, error) {
			return comms, nil
		}

		subscription := eth2exp.BeaconCommitteeSubscription{
			ValidatorIndex: eth2p0.ValidatorIndex(1),
			Slot:           slot,
			CommitteeIndex: commIdx,
			SlotSignature:  blssig,
		}

		resp, err := eth2exp.CalculateCommitteeSubscriptionResponse(ctx, bmock, subscription)
		require.NoError(t, err)
		require.Equal(t, resp.ValidatorIndex, subscription.ValidatorIndex)
		require.True(t, resp.IsAggregator)
	})

	t.Run("is not aggregator", func(t *testing.T) {
		commLen := 61
		var vals []eth2p0.ValidatorIndex
		for idx := 1; idx <= commLen; idx++ {
			vals = append(vals, eth2p0.ValidatorIndex(idx))
		}
		comms := []*eth2v1.BeaconCommittee{
			{
				Slot:       slot,
				Index:      commIdx,
				Validators: vals,
			},
		}

		bmock.BeaconCommitteesAtEpochFunc = func(_ context.Context, _ string, _ eth2p0.Epoch) ([]*eth2v1.BeaconCommittee, error) {
			return comms, nil
		}

		subscription := eth2exp.BeaconCommitteeSubscription{
			ValidatorIndex: eth2p0.ValidatorIndex(1),
			Slot:           slot,
			CommitteeIndex: commIdx,
			SlotSignature:  blssig,
		}

		resp, err := eth2exp.CalculateCommitteeSubscriptionResponse(ctx, bmock, subscription)
		require.NoError(t, err)
		require.Equal(t, resp.ValidatorIndex, subscription.ValidatorIndex)
		require.False(t, resp.IsAggregator)
	})
}

func TestIsAggregator(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	sig, err := hex.DecodeString("8776a37d6802c4797d113169c5fcfda50e68a32058eb6356a6f00d06d7da64c841a00c7c38b9b94a204751eca53707bd03523ce4797827d9bacff116a6e776a20bbccff4b683bf5201b610797ed0502557a58a65c8395f8a1649b976c3112d15")
	require.NoError(t, err)
	blsSig, err := tblsconv.SigFromBytes(sig)
	require.NoError(t, err)
	eth2Sig := tblsconv.SigToETH2(blsSig)

	t.Run("is aggregator", func(t *testing.T) {
		commLen := 3
		isAgg, err := eth2exp.IsAggregator(context.Background(), bmock, int64(commLen), eth2Sig)
		require.NoError(t, err)
		require.True(t, isAgg)
	})

	t.Run("is not aggregator", func(t *testing.T) {
		commLen := 64
		isAgg, err := eth2exp.IsAggregator(context.Background(), bmock, int64(commLen), eth2Sig)
		require.NoError(t, err)
		require.False(t, isAgg)
	})
}
