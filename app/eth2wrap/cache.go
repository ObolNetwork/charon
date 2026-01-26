// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
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
type ProposerDuties map[eth2p0.Epoch][]*eth2v1.ProposerDuty

// AttesterDuties is a map of attester duties per epoch.
type AttesterDuties map[eth2p0.Epoch][]*eth2v1.AttesterDuty

// SyncDuties is a map of sync committee duties per epoch.
type SyncDuties map[eth2p0.Epoch][]*eth2v1.SyncCommitteeDuty

// CachedDutiesProvider is the interface for providing current epoch's duties.
type CachedDutiesProvider interface {
	UpdateCacheIndices(context.Context, []eth2p0.ValidatorIndex)

	ProposerDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	AttesterDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	SyncCommDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
}

// NewDutiesCache creates a new validator cache.
func NewDutiesCache(eth2Cl Client, validatorIndices []eth2p0.ValidatorIndex) *DutiesCache {
	return &DutiesCache{
		eth2Cl:           eth2Cl,
		validatorIndices: validatorIndices,

		proposerDuties: make(ProposerDuties),
		attesterDuties: make(AttesterDuties),
		syncDuties:     make(SyncDuties),
	}
}

// DutiesCache caches active duties.
type DutiesCache struct {
	eth2Cl           Client
	validatorIndices []eth2p0.ValidatorIndex

	mu             sync.RWMutex
	proposerDuties ProposerDuties
	attesterDuties AttesterDuties
	syncDuties     SyncDuties
}

// Trim trims the cache of 6 epochs older than the current.
// This should be called on epoch boundary.
func (c *DutiesCache) Trim(epoch eth2p0.Epoch) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch < dutiesCacheTrimThreshold {
		return
	}

	proposerDutiesEpochs := slices.Collect(maps.Keys(c.proposerDuties))
	for _, e := range proposerDutiesEpochs {
		if e < epoch-dutiesCacheTrimThreshold {
			delete(c.proposerDuties, e)
		}
	}

	attesterDutiesEpochs := slices.Collect(maps.Keys(c.attesterDuties))
	for _, e := range attesterDutiesEpochs {
		if e < epoch-dutiesCacheTrimThreshold {
			delete(c.attesterDuties, e)
		}
	}

	syncDutiesEpochs := slices.Collect(maps.Keys(c.syncDuties))
	for _, e := range syncDutiesEpochs {
		if e < epoch-dutiesCacheTrimThreshold {
			delete(c.syncDuties, e)
		}
	}
}

// UpdateCacheIndices updates the validator indices to be queried.
func (c *DutiesCache) UpdateCacheIndices(_ context.Context, indices []eth2p0.ValidatorIndex) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.validatorIndices = indices
}

// InvalidateCache handles chain reorg, invalidating cached duties.
// The epoch parameter indicates at which epoch the reorg led us to.
// Meaning, we should invalidate all duties prior to that epoch.
func (c *DutiesCache) InvalidateCache(_ context.Context, epoch eth2p0.Epoch) {
	c.mu.Lock()
	defer c.mu.Unlock()

	invalidated := false
	for e := range c.proposerDuties {
		if e > epoch {
			invalidated = true
			delete(c.proposerDuties, e)
		}
	}

	for e := range c.attesterDuties {
		if e > epoch {
			invalidated = true
			delete(c.attesterDuties, e)
		}
	}

	for e := range c.syncDuties {
		if e > epoch {
			invalidated = true
			delete(c.syncDuties, e)
		}
	}

	if invalidated {
		invalidatedCacheDueReorgCount.WithLabelValues("validators").Inc()
	}
}

// ProposerDutiesCache returns the cached proposer duties, or fetches them if not available populating the cache.
func (c *DutiesCache) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	duties, ok := c.cachedProposerDuties(epoch, vidxs)

	if ok {
		usedCacheCount.WithLabelValues("validators").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("validators").Inc()
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	proposerDutiesCurrEpoch := []*eth2v1.ProposerDuty{}

	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return nil, errors.New("proposer duty data is nil")
		}

		proposerDutiesCurrEpoch = append(proposerDutiesCurrEpoch, duty)
	}

	proposerDuties := c.proposerDuties
	proposerDuties[epoch] = proposerDutiesCurrEpoch
	c.proposerDuties = proposerDuties

	return proposerDutiesCurrEpoch, nil
}

// AttesterDutiesCache returns the cached attester duties, or fetches them if not available populating the cache.
func (c *DutiesCache) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	duties, ok := c.cachedAttesterDuties(epoch, vidxs)

	if ok {
		usedCacheCount.WithLabelValues("validators").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("validators").Inc()
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := &eth2api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	c.attesterDuties[epoch] = eth2Resp.Data

	return eth2Resp.Data, nil
}

// SyncCommDutiesCache returns the cached sync duties, or fetches them if not available populating the cache.
func (c *DutiesCache) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	duties, ok := c.cachedSyncDuties(epoch, vidxs)

	if ok {
		usedCacheCount.WithLabelValues("validators").Inc()
		return duties, nil
	}

	missedCacheCount.WithLabelValues("validators").Inc()
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := &eth2api.SyncCommitteeDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	eth2Resp, err := c.eth2Cl.SyncCommitteeDuties(ctx, opts)
	if err != nil {
		return nil, err
	}

	syncDutiesCurrEpoch := []*eth2v1.SyncCommitteeDuty{}

	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return nil, errors.New("sync duty data is nil")
		}

		syncDutiesCurrEpoch = append(syncDutiesCurrEpoch, duty)
	}

	syncDuties := c.syncDuties
	syncDuties[epoch] = syncDutiesCurrEpoch
	c.syncDuties = syncDuties

	return syncDutiesCurrEpoch, nil
}

// cachedProposerDuties returns the cached proposer duties and true if they are available.
func (c *DutiesCache) cachedProposerDuties(epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	duties, ok := c.proposerDuties[epoch]
	if !ok {
		return nil, false
	}

	if len(vidxs) == 0 {
		return duties, true
	}

	dutiesFiltered := []*eth2v1.ProposerDuty{}
	for _, d := range duties {
		if !slices.Contains(vidxs, d.ValidatorIndex) {
			continue
		}
		dutiesFiltered = append(dutiesFiltered, d)
	}

	return dutiesFiltered, true
}

// cachedAttesterDuties returns the cached attester duties and true if they are available.
func (c *DutiesCache) cachedAttesterDuties(epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	duties, ok := c.attesterDuties[epoch]
	if !ok {
		return nil, false
	}

	if len(vidxs) == 0 {
		return duties, true
	}

	dutiesFiltered := []*eth2v1.AttesterDuty{}
	for _, d := range duties {
		if !slices.Contains(vidxs, d.ValidatorIndex) {
			continue
		}
		dutiesFiltered = append(dutiesFiltered, d)
	}

	return dutiesFiltered, true
}

// cachedSyncDuties returns the cached sync duties and true if they are available.
func (c *DutiesCache) cachedSyncDuties(epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	duties, ok := c.syncDuties[epoch]
	if !ok {
		return nil, false
	}

	if len(vidxs) == 0 {
		return duties, true
	}

	dutiesFiltered := []*eth2v1.SyncCommitteeDuty{}
	for _, d := range duties {
		if !slices.Contains(vidxs, d.ValidatorIndex) {
			continue
		}
		dutiesFiltered = append(dutiesFiltered, d)
	}

	return dutiesFiltered, true
}
