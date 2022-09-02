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

package beaconmock_test

import (
	"context"
	"testing"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test . -update

func TestDeterministicAttesterDuties(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithDeterministicAttesterDuties(1),
	)
	require.NoError(t, err)

	attDuty, err := bmock.AttesterDuties(context.Background(), 1, []eth2p0.ValidatorIndex{2})
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, attDuty)
}

func TestDeterministicProposerDuties(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithValidatorSet(beaconmock.ValidatorSetA),
		beaconmock.WithDeterministicProposerDuties(1),
	)
	require.NoError(t, err)

	proDuty, err := bmock.ProposerDuties(context.Background(), 1, []eth2p0.ValidatorIndex{2})
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, proDuty)
}

func TestAttestationData(t *testing.T) {
	bmock, err := beaconmock.New(
		beaconmock.WithClock(clockwork.NewFakeClockAt(time.Date(2022, 3, 20, 1, 0, 0, 0, time.UTC))),
	)
	require.NoError(t, err)

	attData, err := bmock.AttestationData(context.Background(), 1, 2)
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, attData)
}

func TestBeaconCommitteeSubscriptions(t *testing.T) {
	const (
		slotA = 123
		slotB = 456
		vIdxA = 1
		vIdxB = 2
		vIdxC = 3
	)

	aggregators := map[eth2p0.Slot]eth2p0.ValidatorIndex{
		slotA: vIdxA,
		slotB: vIdxB,
	}

	bmock, err := beaconmock.New(beaconmock.WithAttestationAggregation(aggregators))
	require.NoError(t, err)

	expected := []eth2exp.BeaconCommitteeSubscriptionResponse{
		{ValidatorIndex: vIdxA, IsAggregator: true},
		{ValidatorIndex: vIdxB, IsAggregator: true},
		{ValidatorIndex: vIdxC, IsAggregator: false},
	}

	subs := []*eth2exp.BeaconCommitteeSubscription{
		{Slot: slotA, ValidatorIndex: vIdxA},
		{Slot: slotB, ValidatorIndex: vIdxB},
		{Slot: slotA, ValidatorIndex: vIdxC},
	}

	actual, err := bmock.SubmitBeaconCommitteeSubscriptions(context.Background(), subs)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
