// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"strconv"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// dutiesCacheTrimThreshold is the number of epochs after which duties are trimmed from the cache.
// Ethereum is usually considered final after all validators signed twice, which is at most 3 epochs minus 1 slot.
// There is no need to keep duties older than that, as usually the validator client does not request.
const dutiesCacheTrimThreshold = 3

// ActiveValidators is a map of active validator indices to pubkeys.
type ActiveValidators map[eth2p0.ValidatorIndex]eth2p0.BLSPubKey

// CompleteValidators represents the complete response of the beacon node validators endpoint.
type CompleteValidators map[eth2p0.ValidatorIndex]*eth2v1.Validator

// Pubkeys returns a list of active validator pubkeys.
func (m ActiveValidators) Pubkeys() []eth2p0.BLSPubKey {
	var pubkeys []eth2p0.BLSPubKey
	for _, pubkey := range m {
		pubkeys = append(pubkeys, pubkey)
	}

	return pubkeys
}

// Indices returns a list of active validator indices.
func (m ActiveValidators) Indices() []eth2p0.ValidatorIndex {
	var indices []eth2p0.ValidatorIndex
	for index := range m {
		indices = append(indices, index)
	}

	return indices
}

// CachedValidatorsProvider is the interface for providing current epoch's cached active validator
// identity information.
type CachedValidatorsProvider interface {
	ActiveValidators(context.Context) (ActiveValidators, error)
	CompleteValidators(context.Context) (CompleteValidators, error)
}

// NewValidatorCache creates a new validator cache.
func NewValidatorCache(eth2Cl Client, pubkeys []eth2p0.BLSPubKey) *ValidatorCache {
	return &ValidatorCache{
		eth2Cl:  eth2Cl,
		pubkeys: pubkeys,
	}
}

// ValidatorCache caches active validators.
type ValidatorCache struct {
	eth2Cl  Client
	pubkeys []eth2p0.BLSPubKey

	mu       sync.RWMutex
	active   ActiveValidators
	complete CompleteValidators
}

// Trim trims the cache.
// This should be called on epoch boundary.
func (c *ValidatorCache) Trim() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.active = nil
	c.complete = nil
}

// activeCached returns the cached active validators and true if they are available.
func (c *ValidatorCache) activeCached() (ActiveValidators, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.active, c.active != nil
}

// cached returns the cached complete validators and true if they are available.
func (c *ValidatorCache) cached() (CompleteValidators, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.complete, c.complete != nil
}

// GetByHead returns the cached active validators, cached complete Validators response, or fetches them if not available populating the cache.
func (c *ValidatorCache) GetByHead(ctx context.Context) (ActiveValidators, CompleteValidators, error) {
	completeCached, completeOk := c.cached()
	activeCached, activeOk := c.activeCached()

	if completeOk && activeOk {
		usedCacheCount.WithLabelValues("validators").Inc()
		return activeCached, completeCached, nil
	}

	missedCacheCount.WithLabelValues("validators").Inc()

	// This code is only ever invoked by scheduler's slot ticking method.
	// It's fine locking this way.
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := &eth2api.ValidatorsOpts{
		State:   "head",
		PubKeys: c.pubkeys,
	}

	eth2Resp, err := c.eth2Cl.Validators(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	vals := eth2Resp.Data

	resp := make(ActiveValidators)

	for _, val := range vals {
		if val == nil || val.Validator == nil {
			return nil, nil, errors.New("validator data is nil")
		}

		if !val.Status.IsActive() {
			continue
		}

		resp[val.Index] = val.Validator.PublicKey
	}

	c.active = resp
	c.complete = eth2Resp.Data

	return resp, eth2Resp.Data, nil
}

// GetBySlot fetches active and complete validator by slot populating the cache.
// If it fails to fetch by slot, it falls back to head state and retries to fetch by slot next slot.
func (c *ValidatorCache) GetBySlot(ctx context.Context, slot uint64) (ActiveValidators, CompleteValidators, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	missedCacheCount.WithLabelValues("validators").Inc()

	refreshedBySlot := true

	opts := &eth2api.ValidatorsOpts{
		State:   strconv.FormatUint(slot, 10),
		PubKeys: c.pubkeys,
	}

	eth2Resp, err := c.eth2Cl.Validators(ctx, opts)
	if err != nil {
		// Failed to fetch by slot, fall back to head state
		refreshedBySlot = false
		opts.State = "head"

		eth2Resp, err = c.eth2Cl.Validators(ctx, opts)
		if err != nil {
			return nil, nil, refreshedBySlot, err
		}
	}

	complete := eth2Resp.Data

	active := make(ActiveValidators)

	for _, val := range complete {
		if val == nil || val.Validator == nil {
			return nil, nil, refreshedBySlot, errors.New("validator data is nil")
		}

		if !val.Status.IsActive() {
			continue
		}

		active[val.Index] = val.Validator.PublicKey
	}

	c.active = active
	c.complete = complete

	return active, complete, refreshedBySlot, nil
}

// ProposerDuties is a map of proposer duties per epoch.
type ProposerDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]*eth2v1.ProposerDuty
}

// AttesterDuties is a map of attester duties per epoch.
type AttesterDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]*eth2v1.AttesterDuty
}

// SyncDuties is a map of sync committee duties per epoch.
type SyncDuties struct {
	mu     sync.RWMutex
	duties map[eth2p0.Epoch][]*eth2v1.SyncCommitteeDuty
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
			duties: make(map[eth2p0.Epoch][]*eth2v1.ProposerDuty),
		},
		attesterDuties: AttesterDuties{
			duties: make(map[eth2p0.Epoch][]*eth2v1.AttesterDuty),
		},
		syncDuties: SyncDuties{
			duties: make(map[eth2p0.Epoch][]*eth2v1.SyncCommitteeDuty),
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
// The epoch parameter indicates at which epoch the reorg led us to.
// Meaning, we should invalidate all duties prior to that epoch.
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

// ProposerDutiesCache returns the cached proposer duties, or fetches them if not available populating the cache.
func (c *DutiesCache) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	// if featureset.Enabled(featureset.DisableDutiesCache) {
	// 	log.Debug(ctx, "dutiescache proposer - disabled, calling proposer duties endpoint")
	// 	eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, &eth2api.ProposerDutiesOpts{Epoch: epoch, Indices: vidxs})
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return eth2Resp.Data, nil
	// }
	start := time.Now()
	log.Debug(ctx, "dutiescache proposer step 1 - checking cache for proposer duties", z.U64("epoch", uint64(epoch)))
	defer func(t time.Time) {
		log.Debug(ctx, "dutiescache proposer step 7 - fetched cache for proposer duties", z.I64("duration_ms", time.Since(t).Milliseconds()), z.U64("epoch", uint64(epoch)))
	}(start)

	duties, ok := c.fetchProposerDuties(epoch)

	if ok {
		usedCacheCount.WithLabelValues("proposer_duties").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("proposer_duties").Inc()

	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	log.Debug(ctx, "dutiescache proposer step 5 - calling proposer duties endpoint", z.U64("epoch", uint64(epoch)))
	eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	log.Debug(ctx, "dutiescache proposer step 6 - caching proposer duties", z.U64("epoch", uint64(epoch)), z.Int("duties", len(eth2Resp.Data)), z.Int("cached_epochs_count", len(c.proposerDuties.duties)+1))
	c.proposerDuties.mu.Lock()
	c.proposerDuties.duties[epoch] = eth2Resp.Data
	c.proposerDuties.mu.Unlock()

	return eth2Resp.Data, nil
}

// AttesterDutiesCache returns the cached attester duties, or fetches them if not available populating the cache.
func (c *DutiesCache) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	if featureset.Enabled(featureset.DisableDutiesCache) {
		eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, &eth2api.AttesterDutiesOpts{Epoch: epoch, Indices: vidxs})
		if err != nil {
			return nil, err
		}

		return eth2Resp.Data, nil
	}

	duties, ok := c.fetchAttesterDuties(epoch)

	if ok {
		usedCacheCount.WithLabelValues("attester_duties").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("attester_duties").Inc()

	opts := &eth2api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	c.attesterDuties.mu.Lock()
	c.attesterDuties.duties[epoch] = eth2Resp.Data
	c.attesterDuties.mu.Unlock()

	return eth2Resp.Data, nil
}

// SyncCommDutiesCache returns the cached sync duties, or fetches them if not available populating the cache.
func (c *DutiesCache) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	if featureset.Enabled(featureset.DisableDutiesCache) {
		eth2Resp, err := c.eth2Cl.SyncCommitteeDuties(ctx, &eth2api.SyncCommitteeDutiesOpts{Epoch: epoch, Indices: vidxs})
		if err != nil {
			return nil, err
		}

		return eth2Resp.Data, nil
	}

	duties, ok := c.fetchSyncDuties(epoch)

	if ok {
		usedCacheCount.WithLabelValues("sync_committee_duties").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("sync_committee_duties").Inc()

	opts := &eth2api.SyncCommitteeDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	eth2Resp, err := c.eth2Cl.SyncCommitteeDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	c.syncDuties.mu.Lock()
	c.syncDuties.duties[epoch] = eth2Resp.Data
	c.syncDuties.mu.Unlock()

	return eth2Resp.Data, nil
}

// fetchProposerDuties returns the cached proposer duties and true if they are available.
func (c *DutiesCache) fetchProposerDuties(epoch eth2p0.Epoch) ([]*eth2v1.ProposerDuty, bool) {
	log.Debug(context.Background(), "dutiescache proposer step 2 - get proposer duties from map", z.U64("epoch", uint64(epoch)))

	c.proposerDuties.mu.RLock()
	defer c.proposerDuties.mu.RUnlock()

	duties, ok := c.proposerDuties.duties[epoch]
	if !ok {
		log.Debug(context.Background(), "dutiescache proposer step 3 and 4 - get proposer duties from map - not found cached epoch", z.U64("epoch", uint64(epoch)))
		return nil, false
	}

	log.Debug(context.Background(), "dutiescache proposer step 3 - get proposer duties from map - found cached epoch, duplicating...", z.U64("epoch", uint64(epoch)), z.Int("duties", len(duties)), z.Int("cached_epochs_count", len(c.proposerDuties.duties)))
	duplicate := make([]*eth2v1.ProposerDuty, 0, len(duties))
	for _, duty := range duties {
		if duty == nil {
			return nil, false
		}
		d := *duty
		duplicate = append(duplicate, &d)
	}
	log.Debug(context.Background(), "dutiescache proposer step 4-6 - duplicated proposer duties", z.U64("epoch", uint64(epoch)))
	return duplicate, true
}

// fetchAttesterDuties returns the cached attester duties and true if they are available.
func (c *DutiesCache) fetchAttesterDuties(epoch eth2p0.Epoch) ([]*eth2v1.AttesterDuty, bool) {
	c.attesterDuties.mu.RLock()
	defer c.attesterDuties.mu.RUnlock()

	duties, ok := c.attesterDuties.duties[epoch]
	if !ok {
		return nil, false
	}

	return duties, true
}

// fetchSyncDuties returns the cached sync duties and true if they are available.
func (c *DutiesCache) fetchSyncDuties(epoch eth2p0.Epoch) ([]*eth2v1.SyncCommitteeDuty, bool) {
	c.syncDuties.mu.RLock()
	defer c.syncDuties.mu.RUnlock()

	duties, ok := c.syncDuties.duties[epoch]
	if !ok {
		return nil, false
	}

	return duties, true
}

// trimBeforeProposerDuties removes cached proposer duties before the given epoch.
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

// trimBeforeAttesterDuties removes cached attester duties before the given epoch.
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

// trimBeforeSyncDuties removes cached sync duties before the given epoch.
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

// trimAfterProposerDuties removes cached proposer duties after the given epoch.
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

// trimAfterAttesterDuties removes cached attester duties after the given epoch.
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

// trimAfterSyncDuties removes cached sync duties after the given epoch.
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
