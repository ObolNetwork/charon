// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// dutiesCacheTrimThreshold is the number of epochs after which duties are trimmed from the cache.
// Ethereum is usually considered final after all validators signed twice, which is at most 3 epochs minus 1 slot.
// There is no need to keep duties older than that, as usually the validator client does not request.
const dutiesCacheTrimThreshold = 3

// ProposerDuties is a map of proposer duties per epoch.
type ProposerDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]eth2v1.ProposerDuty
}

// AttesterDuties is a map of attester duties per epoch.
type AttesterDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]eth2v1.AttesterDuty
}

// SyncDuties is a map of sync committee duties per epoch.
type SyncDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]eth2v1.SyncCommitteeDuty
}

// CachedDutiesProvider is the interface for providing current epoch's duties.
type CachedDutiesProvider interface {
	ProposerDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	AttesterDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	SyncCommDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
}

// NewDutiesCache creates a new validator cache.
func NewDutiesCache(eth2Cl Client) *DutiesCache {
	return &DutiesCache{
		eth2Cl: eth2Cl,

		proposerDuties: ProposerDuties{
			duties: make(map[eth2p0.Epoch][]eth2v1.ProposerDuty),
		},
		attesterDuties: AttesterDuties{
			duties: make(map[eth2p0.Epoch][]eth2v1.AttesterDuty),
		},
		syncDuties: SyncDuties{
			duties: make(map[eth2p0.Epoch][]eth2v1.SyncCommitteeDuty),
		},
	}
}

// DutiesCache caches active duties.
type DutiesCache struct {
	eth2Cl Client

	proposerDuties ProposerDuties
	attesterDuties AttesterDuties
	syncDuties     SyncDuties
}

// ProposerDutiesCache returns the cached proposer duties, or fetches them if not available, populating the cache with the newly fetched ones.
func (c *DutiesCache) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return nil, errors.New("proposer duties cache is not implemented")
}

// AttesterDutiesCache returns the cached attester duties, or fetches them if not available, populating the cache with the newly fetched ones.
func (c *DutiesCache) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	duties, ok := c.fetchAttesterDuties(epoch)

	if ok {
		usedCacheCount.WithLabelValues("attester_duties").Inc()

		dutiesRef := make([]*eth2v1.AttesterDuty, 0, len(duties))
		for _, d := range duties {
			dutiesRef = append(dutiesRef, &d)
		}

		return dutiesRef, nil
	}

	missedCacheCount.WithLabelValues("attester_duties").Inc()

	eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, &eth2api.AttesterDutiesOpts{Epoch: epoch, Indices: vidxs})
	if err != nil {
		return nil, err
	}

	dutiesDeref := make([]eth2v1.AttesterDuty, 0, len(eth2Resp.Data))
	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return nil, errors.New("attester duty is nil")
		}

		d := *duty
		dutiesDeref = append(dutiesDeref, d)
	}

	ok = c.storeAttesterDuties(epoch, dutiesDeref)
	if !ok {
		log.Debug(ctx, "failed to cache attester duties - another routine already cached duties for this epoch, skipping", z.U64("epoch", uint64(epoch)))
	}

	return eth2Resp.Data, nil
}

// SyncCommDutiesCache returns the cached sync duties, or fetches them if not available, populating the cache with the newly fetched ones.
func (c *DutiesCache) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	return nil, errors.New("sync committee duties cache is not implemented")
}

// Trim trims the cache of 3 epochs older than the current.
// This should be called on epoch boundary.
func (c *DutiesCache) Trim(epoch eth2p0.Epoch) {
	if epoch < dutiesCacheTrimThreshold {
		return
	}

	c.trimBeforeProposerDuties(epoch - dutiesCacheTrimThreshold)
	c.trimBeforeAttesterDuties(epoch - dutiesCacheTrimThreshold)
	c.trimBeforeSyncDuties(epoch - dutiesCacheTrimThreshold)
}

// InvalidateCache handles chain reorg, invalidating cached duties.
// The epoch parameter indicates the epoch the chain has reorged back to.
// Meaning, we should invalidate all duties after that epoch.
func (c *DutiesCache) InvalidateCache(ctx context.Context, epoch eth2p0.Epoch) {
	invalidated := false

	ok := c.trimAfterProposerDuties(epoch)
	if ok {
		invalidated = true
	}

	ok = c.trimAfterAttesterDuties(epoch)
	if ok {
		invalidated = true
	}

	ok = c.trimAfterSyncDuties(epoch)
	if ok {
		invalidated = true
	}

	if invalidated {
		log.Debug(ctx, "reorg occurred through epoch transition, invalidating duties cache", z.U64("reorged_back_to_epoch", uint64(epoch)))
		invalidatedCacheDueReorgCount.WithLabelValues("validators").Inc()
	} else {
		log.Debug(ctx, "reorg occurred, but it was not through epoch transition, duties cache is not invalidated", z.U64("reorged_epoch", uint64(epoch)))
	}
}

// fetchAttesterDuties returns the cached attester duties and true if they are available.
func (c *DutiesCache) fetchAttesterDuties(epoch eth2p0.Epoch) ([]eth2v1.AttesterDuty, bool) {
	c.attesterDuties.mu.RLock()
	defer c.attesterDuties.mu.RUnlock()

	duties, ok := c.attesterDuties.duties[epoch]
	if !ok {
		return nil, false
	}

	return duties, true
}

// storeAttesterDuties stores attester duties in the cache for the given epoch if they don't exist and false if they already exists.
func (c *DutiesCache) storeAttesterDuties(epoch eth2p0.Epoch, duties []eth2v1.AttesterDuty) bool {
	c.attesterDuties.mu.Lock()
	defer c.attesterDuties.mu.Unlock()

	_, ok := c.attesterDuties.duties[epoch]
	if ok {
		return false
	}

	c.attesterDuties.duties[epoch] = duties

	return true
}

// trimBeforeProposerDuties removes cached proposer duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeProposerDuties(epoch eth2p0.Epoch) bool {
	c.proposerDuties.mu.Lock()
	defer c.proposerDuties.mu.Unlock()

	ok := false

	for k := range c.proposerDuties.duties {
		if k < epoch {
			delete(c.proposerDuties.duties, k)

			ok = true
		}
	}

	return ok
}

// trimBeforeAttesterDuties removes cached attester duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeAttesterDuties(epoch eth2p0.Epoch) bool {
	c.attesterDuties.mu.Lock()
	defer c.attesterDuties.mu.Unlock()

	ok := false

	for k := range c.attesterDuties.duties {
		if k < epoch {
			delete(c.attesterDuties.duties, k)

			ok = true
		}
	}

	return ok
}

// trimBeforeSyncDuties removes cached sync duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeSyncDuties(epoch eth2p0.Epoch) bool {
	c.syncDuties.mu.Lock()
	defer c.syncDuties.mu.Unlock()

	ok := false

	for k := range c.syncDuties.duties {
		if k < epoch {
			delete(c.syncDuties.duties, k)

			ok = true
		}
	}

	return ok
}

// trimAfterProposerDuties removes cached proposer duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterProposerDuties(epoch eth2p0.Epoch) bool {
	c.proposerDuties.mu.Lock()
	defer c.proposerDuties.mu.Unlock()

	ok := false

	for k := range c.proposerDuties.duties {
		if k > epoch {
			delete(c.proposerDuties.duties, k)

			ok = true
		}
	}

	return ok
}

// trimAfterAttesterDuties removes cached attester duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterAttesterDuties(epoch eth2p0.Epoch) bool {
	c.attesterDuties.mu.Lock()
	defer c.attesterDuties.mu.Unlock()

	ok := false

	for k := range c.attesterDuties.duties {
		if k > epoch {
			delete(c.attesterDuties.duties, k)

			ok = true
		}
	}

	return ok
}

// trimAfterSyncDuties removes cached sync duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterSyncDuties(epoch eth2p0.Epoch) bool {
	c.syncDuties.mu.Lock()
	defer c.syncDuties.mu.Unlock()

	ok := false

	for k := range c.syncDuties.duties {
		if k > epoch {
			delete(c.syncDuties.duties, k)

			ok = true
		}
	}

	return ok
}
