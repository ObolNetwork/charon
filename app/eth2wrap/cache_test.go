// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"maps"
	"math/rand"
	"slices"
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
	eth2Cl, err := beaconmock.New(t.Context())
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
	actual, complete, err := valCache.GetByHead(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)
	require.Equal(t, completeExpected, complete)

	// Check cache is used.
	actual, complete, err = valCache.GetByHead(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 1, queried)
	require.Equal(t, completeExpected, complete)

	// Trim cache.
	valCache.Trim()

	// Check cache is populated again.
	actual, complete, err = valCache.GetByHead(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)
	require.Equal(t, completeExpected, complete)

	// Check cache is used again.
	actual, complete, err = valCache.GetByHead(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 2, queried)
	require.Equal(t, completeExpected, complete)
}

func TestGetBySlot(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		// Create a mock client.
		eth2Cl, err := beaconmock.New(t.Context())
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
		ctx := t.Context()

		active, complete, refreshedBySlot, err := valCache.GetBySlot(ctx, 1)
		require.NoError(t, err)
		require.Len(t, active, 1)
		require.Equal(t, pubkeys[1], active[1])
		require.Len(t, complete, 2)
		require.True(t, refreshedBySlot)

		active, complete, refreshedBySlot, err = valCache.GetBySlot(ctx, 2)
		require.NoError(t, err)
		require.Len(t, active, 2)
		require.Len(t, complete, 2)
		require.True(t, refreshedBySlot)

		active, complete, refreshedBySlot, err = valCache.GetBySlot(ctx, 11)
		require.NoError(t, err)
		require.Empty(t, active)
		require.Len(t, complete, 2)
		require.True(t, refreshedBySlot)

		_, _, refreshedBySlot, err = valCache.GetBySlot(ctx, 3)
		require.Error(t, err)
		require.False(t, refreshedBySlot)
	})

	t.Run("fallback to head state", func(t *testing.T) {
		// Create a mock client.
		eth2Cl, err := beaconmock.New(t.Context())
		require.NoError(t, err)

		// Create two validators pubkeys
		pubkeys := []eth2p0.BLSPubKey{
			testutil.RandomEth2PubKey(t),
			testutil.RandomEth2PubKey(t),
		}

		eth2Cl.ValidatorsFunc = func(ctx context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			switch opts.State {
			case "head":
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
			default:
				return beaconmock.ValidatorSet{}, errors.New("no slot found")
			}
		}

		valCache := eth2wrap.NewValidatorCache(eth2Cl, pubkeys)
		ctx := t.Context()

		active, complete, refreshedBySlot, err := valCache.GetBySlot(ctx, 1)
		require.NoError(t, err)
		require.Len(t, active, 2)
		require.Len(t, complete, 2)
		require.False(t, refreshedBySlot)
	})
}

func TestDutiesCache(t *testing.T) {
	NValidators := 64
	// Create a set of validators
	valSet := testutil.RandomValidatorSet(t, NValidators)

	proposerDutiesCalled := false

	// Create a mock client.
	eth2Cl, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	eth2Cl.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
		resp := []*eth2v1.ProposerDuty{}

		for idx, vidx := range vidxs {
			validator := *valSet[vidxs[rand.Intn(NValidators)]]
			resp = append(resp, &eth2v1.ProposerDuty{
				PubKey:         validator.Validator.PublicKey,
				ValidatorIndex: vidx,
				Slot:           eth2p0.Slot(idx),
			})
		}

		proposerDutiesCalled = true

		return resp, nil
	}

	// Create a cache.
	valCache := eth2wrap.NewDutiesCache(eth2Cl, slices.Collect(maps.Keys(valSet)))
	ctx := t.Context()

	// First call should populate the cache
	_, err = valCache.ProposerDutiesCache(ctx, 0, slices.Collect(maps.Keys(valSet)))
	require.NoError(t, err)
	require.True(t, proposerDutiesCalled)

	// Second call should use the cache
	proposerDutiesCalled = false
	_, err = valCache.ProposerDutiesCache(ctx, 0, slices.Collect(maps.Keys(valSet)))
	require.NoError(t, err)
	require.False(t, proposerDutiesCalled)

	// Trim cache
	valCache.Trim(7)

	// Third call should populate the cache
	_, err = valCache.ProposerDutiesCache(ctx, 0, slices.Collect(maps.Keys(valSet)))
	require.NoError(t, err)
	require.True(t, proposerDutiesCalled)
}

// cacheAdapter captures the per-duty-type differences needed to exercise DutiesCache
// under the shared scenario runners below. installBN wires the mock's duty endpoint to
// record every call's indices and return one duty per requested index; callCache
// invokes the matching cache method and returns the number of duties in the response.
type cacheAdapter struct {
	installBN func(m *beaconmock.Mock, record func([]eth2p0.ValidatorIndex), valSet beaconmock.ValidatorSet)
	callCache func(c *eth2wrap.DutiesCache, ctx context.Context, vidxs []eth2p0.ValidatorIndex) (int, error)
}

func proposerCacheAdapter() cacheAdapter {
	return cacheAdapter{
		installBN: func(m *beaconmock.Mock, record func([]eth2p0.ValidatorIndex), valSet beaconmock.ValidatorSet) {
			m.ProposerDutiesFunc = func(_ context.Context, _ eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
				record(vidxs)

				resp := make([]*eth2v1.ProposerDuty, 0, len(vidxs))
				for _, vidx := range vidxs {
					val, ok := valSet[vidx]
					if !ok {
						continue
					}

					resp = append(resp, &eth2v1.ProposerDuty{
						PubKey:         val.Validator.PublicKey,
						ValidatorIndex: vidx,
					})
				}

				return resp, nil
			}
		},
		callCache: func(c *eth2wrap.DutiesCache, ctx context.Context, vidxs []eth2p0.ValidatorIndex) (int, error) {
			r, err := c.ProposerDutiesCache(ctx, 0, vidxs)
			return len(r.Duties), err
		},
	}
}

func attesterCacheAdapter() cacheAdapter {
	return cacheAdapter{
		installBN: func(m *beaconmock.Mock, record func([]eth2p0.ValidatorIndex), valSet beaconmock.ValidatorSet) {
			m.AttesterDutiesFunc = func(_ context.Context, _ eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
				record(vidxs)

				resp := make([]*eth2v1.AttesterDuty, 0, len(vidxs))
				for _, vidx := range vidxs {
					val, ok := valSet[vidx]
					if !ok {
						continue
					}

					resp = append(resp, &eth2v1.AttesterDuty{
						PubKey:         val.Validator.PublicKey,
						ValidatorIndex: vidx,
					})
				}

				return resp, nil
			}
		},
		callCache: func(c *eth2wrap.DutiesCache, ctx context.Context, vidxs []eth2p0.ValidatorIndex) (int, error) {
			r, err := c.AttesterDutiesCache(ctx, 0, vidxs)
			return len(r.Duties), err
		},
	}
}

func syncCommitteeCacheAdapter() cacheAdapter {
	return cacheAdapter{
		installBN: func(m *beaconmock.Mock, record func([]eth2p0.ValidatorIndex), valSet beaconmock.ValidatorSet) {
			m.SyncCommitteeDutiesFunc = func(_ context.Context, _ eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
				record(vidxs)

				resp := make([]*eth2v1.SyncCommitteeDuty, 0, len(vidxs))
				for _, vidx := range vidxs {
					val, ok := valSet[vidx]
					if !ok {
						continue
					}

					resp = append(resp, &eth2v1.SyncCommitteeDuty{
						PubKey:         val.Validator.PublicKey,
						ValidatorIndex: vidx,
					})
				}

				return resp, nil
			}
		},
		callCache: func(c *eth2wrap.DutiesCache, ctx context.Context, vidxs []eth2p0.ValidatorIndex) (int, error) {
			r, err := c.SyncCommDutiesCache(ctx, 0, vidxs)
			return len(r.Duties), err
		},
	}
}

// newCacheHarness builds a DutiesCache wired to a beaconmock whose duty endpoint (as
// installed by the adapter) records every call. It returns the cache, the sorted list
// of all validator indices, and a pointer to the growing slice of recorded BN calls.
func newCacheHarness(t *testing.T, nValidators int, a cacheAdapter) (*eth2wrap.DutiesCache, []eth2p0.ValidatorIndex, *[][]eth2p0.ValidatorIndex) {
	t.Helper()

	valSet := testutil.RandomValidatorSet(t, nValidators)
	allIdxs := slices.Collect(maps.Keys(valSet))
	slices.Sort(allIdxs)

	eth2Cl, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(valSet))
	require.NoError(t, err)

	var bnCalls [][]eth2p0.ValidatorIndex

	a.installBN(&eth2Cl, func(vidxs []eth2p0.ValidatorIndex) {
		bnCalls = append(bnCalls, slices.Clone(vidxs))
	}, valSet)

	return eth2wrap.NewDutiesCache(eth2Cl, allIdxs), allIdxs, &bnCalls
}

func sortedIdxs(idxs []eth2p0.ValidatorIndex) []eth2p0.ValidatorIndex {
	out := slices.Clone(idxs)
	slices.Sort(out)

	return out
}

// runAllThenAllCached covers: cache empty -> request all validators causes a single BN
// fetch; a second request for all validators is fully served from the cache.
func runAllThenAllCached(t *testing.T, a cacheAdapter) {
	t.Helper()

	const nValidators = 8

	cache, allIdxs, bnCalls := newCacheHarness(t, nValidators, a)
	ctx := t.Context()

	// Call 1: all validators -> cache miss, BN fetch for all.
	count, err := a.callCache(cache, ctx, slices.Clone(allIdxs))
	require.NoError(t, err)
	require.Equal(t, nValidators, count)
	require.Len(t, *bnCalls, 1)
	require.Equal(t, allIdxs, sortedIdxs((*bnCalls)[0]))

	// Call 2: all validators -> fully served from cache, no BN call.
	count, err = a.callCache(cache, ctx, slices.Clone(allIdxs))
	require.NoError(t, err)
	require.Equal(t, nValidators, count)
	require.Len(t, *bnCalls, 1, "cache should serve without hitting the beacon node")
}

// runSingleThenAllThenCached covers: cache empty -> request one validator X causes a BN
// fetch for [X]; a follow-up request for all validators causes a BN fetch for
// all-except-X; a subsequent request for a now-cached validator Y is served entirely
// from the cache.
func runSingleThenAllThenCached(t *testing.T, a cacheAdapter) {
	t.Helper()

	const nValidators = 8

	cache, allIdxs, bnCalls := newCacheHarness(t, nValidators, a)
	ctx := t.Context()

	x := allIdxs[0]
	y := allIdxs[1]

	// Call 1: validator X only -> BN fetch [X].
	count, err := a.callCache(cache, ctx, []eth2p0.ValidatorIndex{x})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, *bnCalls, 1)
	require.Equal(t, []eth2p0.ValidatorIndex{x}, (*bnCalls)[0])

	// Call 2: all validators -> BN fetch for all-except-X; X is served from cache.
	count, err = a.callCache(cache, ctx, slices.Clone(allIdxs))
	require.NoError(t, err)
	require.Equal(t, nValidators, count)
	require.Len(t, *bnCalls, 2)

	expectedSecondCall := slices.DeleteFunc(slices.Clone(allIdxs), func(i eth2p0.ValidatorIndex) bool {
		return i == x
	})
	require.Equal(t, expectedSecondCall, sortedIdxs((*bnCalls)[1]))

	// Call 3: validator Y only -> fully served from cache, no BN call.
	count, err = a.callCache(cache, ctx, []eth2p0.ValidatorIndex{y})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, *bnCalls, 2, "Y was populated by the all-validators call; no BN call expected")
}

// runSingleThenSingleThenAll covers: cache empty -> request one validator X causes a BN
// fetch for [X]; a request for a different validator Y (not yet cached) causes a BN
// fetch for [Y]; a subsequent request for all validators causes a BN fetch for
// all-except-{X,Y} while X and Y are served from the cache.
func runSingleThenSingleThenAll(t *testing.T, a cacheAdapter) {
	t.Helper()

	const nValidators = 8

	cache, allIdxs, bnCalls := newCacheHarness(t, nValidators, a)
	ctx := t.Context()

	x := allIdxs[0]
	y := allIdxs[1]

	// Call 1: validator X -> BN fetch [X].
	count, err := a.callCache(cache, ctx, []eth2p0.ValidatorIndex{x})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, *bnCalls, 1)
	require.Equal(t, []eth2p0.ValidatorIndex{x}, (*bnCalls)[0])

	// Call 2: validator Y (not yet cached) -> BN fetch [Y].
	count, err = a.callCache(cache, ctx, []eth2p0.ValidatorIndex{y})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, *bnCalls, 2)
	require.Equal(t, []eth2p0.ValidatorIndex{y}, (*bnCalls)[1])

	// Call 3: all validators -> BN fetch for all-except-{X,Y}; X and Y come from cache.
	count, err = a.callCache(cache, ctx, slices.Clone(allIdxs))
	require.NoError(t, err)
	require.Equal(t, nValidators, count)
	require.Len(t, *bnCalls, 3)

	expectedThirdCall := slices.DeleteFunc(slices.Clone(allIdxs), func(i eth2p0.ValidatorIndex) bool {
		return i == x || i == y
	})
	require.Equal(t, expectedThirdCall, sortedIdxs((*bnCalls)[2]))
}

func TestProposerDutiesCache_AllValidators(t *testing.T) {
	runAllThenAllCached(t, proposerCacheAdapter())
}

func TestProposerDutiesCache_SingleThenAllThenCached(t *testing.T) {
	runSingleThenAllThenCached(t, proposerCacheAdapter())
}

func TestProposerDutiesCache_SingleThenSingleThenAll(t *testing.T) {
	runSingleThenSingleThenAll(t, proposerCacheAdapter())
}

func TestAttesterDutiesCache_AllValidators(t *testing.T) {
	runAllThenAllCached(t, attesterCacheAdapter())
}

func TestAttesterDutiesCache_SingleThenAllThenCached(t *testing.T) {
	runSingleThenAllThenCached(t, attesterCacheAdapter())
}

func TestAttesterDutiesCache_SingleThenSingleThenAll(t *testing.T) {
	runSingleThenSingleThenAll(t, attesterCacheAdapter())
}

func TestSyncCommDutiesCache_AllValidators(t *testing.T) {
	runAllThenAllCached(t, syncCommitteeCacheAdapter())
}

func TestSyncCommDutiesCache_SingleThenAllThenCached(t *testing.T) {
	runSingleThenAllThenCached(t, syncCommitteeCacheAdapter())
}

func TestSyncCommDutiesCache_SingleThenSingleThenAll(t *testing.T) {
	runSingleThenSingleThenAll(t, syncCommitteeCacheAdapter())
}
