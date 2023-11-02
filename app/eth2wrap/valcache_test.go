// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"math/rand"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestValidatorCache(t *testing.T) {
	var (
		expected = make(eth2wrap.ActiveValidators)
		set      = make(beaconmock.ValidatorSet)
		pubkeys  []eth2p0.BLSPubKey
	)

	// Create a set of validators, half active, half random state.
	for i := 0; i < 10; i++ {
		val := testutil.RandomValidator(t)
		if rand.Intn(2) == 0 {
			val.Status = eth2v1.ValidatorState(rand.Intn(10))
		}
		if val.Status.IsActive() {
			expected[val.Index] = val.Validator.PublicKey
		}
		set[val.Index] = val
		pubkeys = append(pubkeys, val.Validator.PublicKey)
	}

	// Create a mock client.
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	// Configure it to return the set of validators if queried.
	var queried int
	eth2Cl.ValidatorsFunc = func(ctx context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
		queried++
		require.Equal(t, "head", opts.State)
		require.Equal(t, pubkeys, opts.PubKeys)

		return set, nil
	}

	// Create a cache.
	valCache := eth2wrap.NewValidatorCache(eth2Cl, pubkeys)
	ctx := context.Background()

	// Check cache is populated.
	actual, err := valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)

	// Check cache is used.
	actual, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)

	// Trim cache.
	valCache.Trim()

	// Check cache is populated again.
	actual, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)

	// Check cache is used again.
	actual, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)
}
