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

package bcast_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/bcast"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestBroadcastAttestation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	att := testutil.RandomAttestation()
	aggData, err := core.EncodeAttestationAggSignedData(att)
	require.NoError(t, err)

	// Assert output and cancel context
	mock.SubmitAttestationsFunc = func(ctx context.Context, attestations []*eth2p0.Attestation) error {
		require.Len(t, attestations, 1)
		require.Equal(t, att, attestations[0])
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyAttester}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastBeaconBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	block1 := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionPhase0,
		Phase0: &eth2p0.SignedBeaconBlock{
			Message:   testutil.RandomPhase0BeaconBlock(),
			Signature: testutil.RandomEth2Signature(),
		},
	}
	aggData, err := core.EncodeBlockAggSignedData(block1)
	require.NoError(t, err)

	mock.SubmitBeaconBlockFunc = func(ctx context.Context, block2 *spec.VersionedSignedBeaconBlock) error {
		require.Equal(t, block1, block2)
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyProposer}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}

func TestBroadcastExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mock, err := beaconmock.New()
	require.NoError(t, err)

	exit := testutil.RandomExit()
	aggData, err := core.EncodeExitAggSignedData(exit)
	require.NoError(t, err)

	mock.SubmitVoluntaryExitFunc = func(ctx context.Context, exit2 *eth2p0.SignedVoluntaryExit) error {
		require.Equal(t, *exit, *exit2)
		cancel()

		return ctx.Err()
	}

	bcaster, err := bcast.New(ctx, mock)
	require.NoError(t, err)

	err = bcaster.Broadcast(ctx, core.Duty{Type: core.DutyExit}, "", aggData)
	require.ErrorIs(t, err, context.Canceled)

	<-ctx.Done()
}
