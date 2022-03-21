// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package beaconmock_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestStatic(t *testing.T) {
	ctx := context.Background()

	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	gen, err := eth2Cl.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, "2021-03-23 14:00:00 +0000 UTC", gen.GenesisTime.UTC().String())

	config, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(36660), config["ALTAIR_FORK_EPOCH"])

	contract, err := eth2Cl.DepositContract(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(5), contract.ChainID)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(32), slotsPerEpoch)
}

func TestGenesisTimeOverride(t *testing.T) {
	ctx := context.Background()

	t0 := time.Now().Truncate(time.Second)
	eth2Cl, err := beaconmock.New(beaconmock.WithGenesisTime(t0))
	require.NoError(t, err)

	gen, err := eth2Cl.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, t0, gen.GenesisTime)

	t1, err := eth2Cl.GenesisTime(ctx)
	require.NoError(t, err)
	require.Equal(t, t0, t1)
}

func TestSlotsPerEpochOverride(t *testing.T) {
	ctx := context.Background()

	expect := 5
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotsPerEpoch(expect))
	require.NoError(t, err)

	actual, err := eth2Cl.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, actual)

	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, spec["SLOTS_PER_EPOCH"])
}

func TestSlotsDurationOverride(t *testing.T) {
	ctx := context.Background()

	expect := time.Second
	eth2Cl, err := beaconmock.New(beaconmock.WithSlotDuration(expect))
	require.NoError(t, err)

	actual, err := eth2Cl.SlotDuration(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, actual)

	spec, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.EqualValues(t, expect, spec["SECONDS_PER_SLOT"])
}
