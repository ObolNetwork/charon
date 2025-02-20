// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"math/rand"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestValidatorCache(t *testing.T) {
	var (
		expected         = make(eth2wrap.ActiveValidators)
		completeExpected = make(eth2wrap.CompleteValidators)
		set              = make(beaconmock.ValidatorSet)
		pubkeys          []eth2p0.BLSPubKey
	)

	// Create a set of validators, half active, half random state.
	for range 10 {
		val := testutil.RandomValidator(t)
		if rand.Intn(2) == 0 {
			val.Status = eth2v1.ValidatorState(rand.Intn(10))
		}
		if val.Status.IsActive() {
			expected[val.Index] = val.Validator.PublicKey
		}
		set[val.Index] = val
		completeExpected[val.Index] = val
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
	actual, complete, err := valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)
	require.Equal(t, completeExpected, complete)

	// Check cache is used.
	actual, complete, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)
	require.Equal(t, completeExpected, complete)

	// Trim cache.
	valCache.Trim()

	// Check cache is populated again.
	actual, complete, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)
	require.Equal(t, completeExpected, complete)

	// Check cache is used again.
	actual, complete, err = valCache.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)
	require.Equal(t, completeExpected, complete)
}

func TestGetBySlot(t *testing.T) {
	// Create a mock client.
	eth2Cl, err := beaconmock.New()
	require.NoError(t, err)

	// Create two validators pubkeys
	pubkeys := []eth2p0.BLSPubKey{
		testutil.RandomEth2PubKey(t),
		testutil.RandomEth2PubKey(t),
	}

	eth2Cl.ValidatorsFunc = func(ctx context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
		switch opts.State {
		case "1":
			return beaconmock.ValidatorSet{
				0: &eth2v1.Validator{
					Index:  0,
					Status: eth2v1.ValidatorStatePendingQueued,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[0],
					},
				},
				1: &eth2v1.Validator{
					Index:  1,
					Status: eth2v1.ValidatorStateActiveOngoing,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[1],
					},
				},
			}, nil
		case "2":
			return beaconmock.ValidatorSet{
				0: &eth2v1.Validator{
					Index:  0,
					Status: eth2v1.ValidatorStateActiveOngoing,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[0],
					},
				},
				1: &eth2v1.Validator{
					Index:  1,
					Status: eth2v1.ValidatorStateActiveOngoing,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[1],
					},
				},
			}, nil
		case "11":
			return beaconmock.ValidatorSet{
				0: &eth2v1.Validator{
					Index:  0,
					Status: eth2v1.ValidatorStatePendingQueued,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[0],
					},
				},
				1: &eth2v1.Validator{
					Index:  1,
					Status: eth2v1.ValidatorStatePendingQueued,
					Validator: &eth2p0.Validator{
						PublicKey: pubkeys[1],
					},
				},
			}, nil

		default:
			return nil, errors.New("no slot found")
		}
	}

	valCache := eth2wrap.NewValidatorCache(eth2Cl, pubkeys)
	ctx := context.Background()

	active, complete, err := valCache.GetBySlot(ctx, 1)
	require.NoError(t, err)
	require.Len(t, active, 1)
	require.Equal(t, pubkeys[1], active[1])
	require.Len(t, complete, 2)

	active, complete, err = valCache.GetBySlot(ctx, 2)
	require.NoError(t, err)
	require.Len(t, active, 2)
	require.Len(t, complete, 2)

	active, complete, err = valCache.GetBySlot(ctx, 11)
	require.NoError(t, err)
	require.Empty(t, active)
	require.Len(t, complete, 2)

	_, _, err = valCache.GetBySlot(ctx, 3)
	require.Error(t, err)
}
