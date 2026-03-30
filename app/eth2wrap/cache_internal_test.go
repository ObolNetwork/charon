// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

// populateDutiesCache seeds all three duty maps with entries for the given epochs.
func populateDutiesCache(t *testing.T, c *DutiesCache, epochs []eth2p0.Epoch) {
	t.Helper()

	for _, epoch := range epochs {
		c.storeOrAmendProposerDuties(epoch, ProposerDutiesForEpoch{
			duties:   []eth2v1.ProposerDuty{{ValidatorIndex: 1}},
			metadata: map[string]any{"epoch": epoch},
		})
		c.storeOrAmendAttesterDuties(epoch, AttesterDutiesForEpoch{
			duties:   []eth2v1.AttesterDuty{{ValidatorIndex: 1}},
			metadata: map[string]any{"epoch": epoch},
		})
		c.storeOrAmendSyncDuties(epoch, SyncDutiesForEpoch{
			duties:   []eth2v1.SyncCommitteeDuty{{ValidatorIndex: 1}},
			metadata: map[string]any{"epoch": epoch},
		})
	}
}

// dutiesCacheLen returns the number of epochs stored in each duty map.
func dutiesCacheLen(c *DutiesCache) (proposer, attester, sync int) {
	c.proposerDuties.RLock()
	proposer1 := len(c.proposerDuties.duties)
	proposer2 := len(c.proposerDuties.metadata)
	proposer3 := len(c.proposerDuties.requestedIdxs)
	proposer = max(proposer1, proposer2, proposer3)

	c.proposerDuties.RUnlock()

	c.attesterDuties.RLock()
	attester1 := len(c.attesterDuties.duties)
	attester2 := len(c.attesterDuties.metadata)
	attester3 := len(c.attesterDuties.requestedIdxs)
	attester = max(attester1, attester2, attester3)

	c.attesterDuties.RUnlock()

	c.syncDuties.RLock()
	sync1 := len(c.syncDuties.duties)
	sync2 := len(c.syncDuties.metadata)
	sync3 := len(c.syncDuties.requestedIdxs)
	sync = max(sync1, sync2, sync3)

	c.syncDuties.RUnlock()

	return proposer, attester, sync
}

// epochCached returns true if the given epoch exists in any of the duty maps.
func epochCached(c *DutiesCache, epoch eth2p0.Epoch) bool {
	cached := []bool{}

	c.proposerDuties.RLock()
	_, ok := c.proposerDuties.duties[epoch]
	cached = append(cached, ok)
	_, ok = c.proposerDuties.metadata[epoch]
	cached = append(cached, ok)
	_, ok = c.proposerDuties.requestedIdxs[epoch]
	cached = append(cached, ok)

	c.proposerDuties.RUnlock()

	c.attesterDuties.RLock()
	_, ok = c.attesterDuties.duties[epoch]
	cached = append(cached, ok)
	_, ok = c.attesterDuties.metadata[epoch]
	cached = append(cached, ok)
	_, ok = c.attesterDuties.requestedIdxs[epoch]
	cached = append(cached, ok)

	c.attesterDuties.RUnlock()

	c.syncDuties.RLock()
	_, ok = c.syncDuties.duties[epoch]
	cached = append(cached, ok)
	_, ok = c.syncDuties.metadata[epoch]
	cached = append(cached, ok)
	_, ok = c.syncDuties.requestedIdxs[epoch]
	cached = append(cached, ok)

	c.syncDuties.RUnlock()

	for _, c := range cached {
		if c {
			return true
		}
	}

	return false
}

// TestDutiesCacheTrimCleansOldEpochs verifies that Trim removes cached entries for epochs
// older than (current - dutiesCacheTrimThreshold), preventing unbounded memory growth.
func TestDutiesCacheTrimCleansOldEpochs(t *testing.T) {
	cache := NewDutiesCache(nil, nil)

	// Seed epochs 0 through 4.
	populateDutiesCache(t, cache, []eth2p0.Epoch{0, 1, 2, 3, 4})

	proposer, attester, sync := dutiesCacheLen(cache)
	require.Equal(t, 5, proposer)
	require.Equal(t, 5, attester)
	require.Equal(t, 5, sync)

	// Trim(6) removes epochs where key < 6-3 = 3, i.e. epochs 0, 1, 2.
	cache.Trim(6)

	proposer, attester, sync = dutiesCacheLen(cache)
	require.Equal(t, 2, proposer, "epochs 0,1,2 should have been trimmed")
	require.Equal(t, 2, attester, "epochs 0,1,2 should have been trimmed")
	require.Equal(t, 2, sync, "epochs 0,1,2 should have been trimmed")

	// Epochs 0, 1, 2 must be gone.
	for _, old := range []eth2p0.Epoch{0, 1, 2} {
		require.False(t, epochCached(cache, old), "epoch %d should have been trimmed", old)
	}

	// Epochs 3 and 4 must still be present.
	for _, keep := range []eth2p0.Epoch{3, 4} {
		require.True(t, epochCached(cache, keep), "epoch %d should still be cached", keep)
	}
}

// TestDutiesCacheTrimBelowThresholdIsNoop verifies that calling Trim with an epoch smaller
// than dutiesCacheTrimThreshold is a no-op and does not clear any cached entries.
func TestDutiesCacheTrimBelowThresholdIsNoop(t *testing.T) {
	cache := NewDutiesCache(nil, nil)

	populateDutiesCache(t, cache, []eth2p0.Epoch{0, 1, 2})

	// epoch=2 < dutiesCacheTrimThreshold(3), so Trim must be a no-op.
	cache.Trim(2)

	proposer, attester, sync := dutiesCacheLen(cache)
	require.Equal(t, 3, proposer, "no entries should be trimmed when epoch < threshold")
	require.Equal(t, 3, attester, "no entries should be trimmed when epoch < threshold")
	require.Equal(t, 3, sync, "no entries should be trimmed when epoch < threshold")
}

// TestDutiesCacheTrimSequential verifies that successive Trim calls at advancing epochs
// progressively clean older entries, leaving only the most recent epochs.
func TestDutiesCacheTrimSequential(t *testing.T) {
	cache := NewDutiesCache(nil, nil)

	populateDutiesCache(t, cache, []eth2p0.Epoch{0, 1, 2, 3, 4, 5})

	// Trim(4): removes epochs < 4-3=1, i.e. epoch 0.
	cache.Trim(4)
	require.False(t, epochCached(cache, 0), "epoch 0 should be trimmed after Trim(4)")
	require.True(t, epochCached(cache, 1), "epoch 1 should still be present after Trim(4)")

	// Trim(6): removes epochs < 6-3=3, i.e. epochs 1 and 2.
	cache.Trim(6)
	require.False(t, epochCached(cache, 1), "epoch 1 should be trimmed after Trim(6)")
	require.False(t, epochCached(cache, 2), "epoch 2 should be trimmed after Trim(6)")
	require.True(t, epochCached(cache, 3), "epoch 3 should still be present after Trim(6)")

	// Trim(8): removes epochs < 8-3=5, i.e. epochs 3 and 4.
	cache.Trim(8)
	require.False(t, epochCached(cache, 3), "epoch 3 should be trimmed after Trim(8)")
	require.False(t, epochCached(cache, 4), "epoch 4 should be trimmed after Trim(8)")
	require.True(t, epochCached(cache, 5), "epoch 5 should still be present after Trim(8)")
}

// TestDutiesCacheRequestedIdxsNoDuplicates verifies that storing duties for the same epoch
// multiple times does not grow requestedIdxs when the indices were already requested,
// even when those indices have no corresponding duty object (e.g. non-proposers).
func TestDutiesCacheRequestedIdxsNoDuplicates(t *testing.T) {
	const epoch = eth2p0.Epoch(5)

	t.Run("proposer", func(t *testing.T) {
		cache := NewDutiesCache(nil, nil)

		// Only validator 1 has a proposer duty; validators 2,3 have none.
		cache.storeOrAmendProposerDuties(epoch, ProposerDutiesForEpoch{
			duties:        []eth2v1.ProposerDuty{{ValidatorIndex: 1}},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{1, 2, 3},
		})

		// Second call with same indices — no new duties (non-proposers return empty).
		cache.storeOrAmendProposerDuties(epoch, ProposerDutiesForEpoch{
			duties:        []eth2v1.ProposerDuty{},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{2, 3},
		})

		cache.proposerDuties.RLock()
		got := len(cache.proposerDuties.requestedIdxs[epoch])
		cache.proposerDuties.RUnlock()

		require.Equal(t, 3, got, "requestedIdxs should not grow when re-requesting already-tracked indices")
	})

	t.Run("attester", func(t *testing.T) {
		cache := NewDutiesCache(nil, nil)

		cache.storeOrAmendAttesterDuties(epoch, AttesterDutiesForEpoch{
			duties:        []eth2v1.AttesterDuty{{ValidatorIndex: 1}},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{1, 2, 3},
		})

		cache.storeOrAmendAttesterDuties(epoch, AttesterDutiesForEpoch{
			duties:        []eth2v1.AttesterDuty{},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{2, 3},
		})

		cache.attesterDuties.RLock()
		got := len(cache.attesterDuties.requestedIdxs[epoch])
		cache.attesterDuties.RUnlock()

		require.Equal(t, 3, got, "requestedIdxs should not grow when re-requesting already-tracked indices")
	})

	t.Run("sync", func(t *testing.T) {
		cache := NewDutiesCache(nil, nil)

		cache.storeOrAmendSyncDuties(epoch, SyncDutiesForEpoch{
			duties:        []eth2v1.SyncCommitteeDuty{{ValidatorIndex: 1}},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{1, 2, 3},
		})

		cache.storeOrAmendSyncDuties(epoch, SyncDutiesForEpoch{
			duties:        []eth2v1.SyncCommitteeDuty{},
			metadata:      map[string]any{},
			requestedIdxs: []eth2p0.ValidatorIndex{2, 3},
		})

		cache.syncDuties.RLock()
		got := len(cache.syncDuties.requestedIdxs[epoch])
		cache.syncDuties.RUnlock()

		require.Equal(t, 3, got, "requestedIdxs should not grow when re-requesting already-tracked indices")
	})
}

func TestDutiesCacheTrimThousandEpochs(t *testing.T) {
	const total = 1000

	cache := NewDutiesCache(nil, nil)

	epochs := make([]eth2p0.Epoch, total)
	for i := range total {
		epochs[i] = eth2p0.Epoch(i)
	}

	populateDutiesCache(t, cache, epochs)

	proposer, attester, sync := dutiesCacheLen(cache)
	require.Equal(t, total, proposer)
	require.Equal(t, total, attester)
	require.Equal(t, total, sync)

	// Trim at epoch 1000: removes all epochs < 1000-3=997, i.e. epochs 0..996.
	trimEpoch := eth2p0.Epoch(total)
	cache.Trim(trimEpoch)

	expectedRemaining := int(dutiesCacheTrimThreshold) // epochs 997, 998, 999
	proposer, attester, sync = dutiesCacheLen(cache)
	require.Equal(t, expectedRemaining, proposer, "only the last %d epochs should remain", expectedRemaining)
	require.Equal(t, expectedRemaining, attester, "only the last %d epochs should remain", expectedRemaining)
	require.Equal(t, expectedRemaining, sync, "only the last %d epochs should remain", expectedRemaining)

	// All old epochs must be gone.
	for i := range total - dutiesCacheTrimThreshold {
		require.False(t, epochCached(cache, eth2p0.Epoch(i)), "epoch %d should have been trimmed", i)
	}

	// The last dutiesCacheTrimThreshold epochs must still be present.
	for i := total - dutiesCacheTrimThreshold; i < total; i++ {
		require.True(t, epochCached(cache, eth2p0.Epoch(i)), "epoch %d should still be cached", i)
	}
}
