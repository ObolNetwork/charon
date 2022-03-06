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
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStatic(t *testing.T) {
	ctx := context.Background()

	eth2Cl, err := beaconmock.NewStaticProvider(ctx)
	require.NoError(t, err)

	gen, err := eth2Cl.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, gen.GenesisTime.UTC().String(), "2020-12-01 12:00:23 +0000 UTC")

	config, err := eth2Cl.Spec(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(74240), config["ALTAIR_FORK_EPOCH"])

	contract, err := eth2Cl.DepositContract(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), contract.ChainID)

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(32), slotsPerEpoch)
}
