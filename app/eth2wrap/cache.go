// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"slices"
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

// CachedDutiesProvider is the interface for providing current epoch's duties.
type CachedDutiesProvider interface {
	ProposerDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	AttesterDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	SyncCommDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
}

// NewDutiesCache creates a new validator cache.
func NewDutiesCache(eth2Cl Client) *DutiesCache {
	return &DutiesCache{eth2Cl: eth2Cl}
}

// DutiesCache caches active duties.
type DutiesCache struct {
	eth2Cl Client

	proposerDuties sync.Map // map[eth2p0.Epoch][]*eth2v1.ProposerDuty
	attesterDuties sync.Map // map[eth2p0.Epoch][]*eth2v1.AttesterDuty
	syncDuties     sync.Map // map[eth2p0.Epoch][]*eth2v1.SyncCommitteeDuty
}

// Trim trims the cache of 3 epochs older than the current.
// This should be called on epoch boundary.
func (c *DutiesCache) Trim(epoch eth2p0.Epoch) error {
	if epoch < dutiesCacheTrimThreshold {
		return nil
	}

	for k := range c.proposerDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			return errors.New("unable to parse proposerDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k))
		}
		if e < epoch-dutiesCacheTrimThreshold {
			c.proposerDuties.Delete(k)
		}
	}

	for k := range c.attesterDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			return errors.New("unable to parse attesterDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k))
		}
		if e < epoch-dutiesCacheTrimThreshold {
			c.attesterDuties.Delete(k)
		}
	}

	for k := range c.syncDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			return errors.New("unable to parse syncDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k))
		}
		if e < epoch-dutiesCacheTrimThreshold {
			c.syncDuties.Delete(k)
		}
	}

	return nil
}

// InvalidateCache handles chain reorg, invalidating cached duties.
// The epoch parameter indicates at which epoch the reorg led us to.
// Meaning, we should invalidate all duties prior to that epoch.
func (c *DutiesCache) InvalidateCache(ctx context.Context, epoch eth2p0.Epoch) {
	invalidated := false

	for k := range c.proposerDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			log.Warn(ctx, "", errors.New("unable to parse proposerDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k)))
		}
		if e > epoch {
			invalidated = true
			c.proposerDuties.Delete(k)
		}
	}

	for k := range c.attesterDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			log.Warn(ctx, "", errors.New("unable to parse proposerDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k)))
		}
		if e > epoch {
			invalidated = true
			c.attesterDuties.Delete(k)
		}
	}

	for k := range c.syncDuties.Range {
		e, ok := k.(eth2p0.Epoch)
		if !ok {
			log.Warn(ctx, "", errors.New("unable to parse syncDuties key to epoch during trim", z.U64("epoch", uint64(epoch)), z.Any("key", k)))
		}
		if e > epoch {
			invalidated = true
			c.syncDuties.Delete(k)
		}
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
	log.Debug(ctx, "dutiescache proposer - checking cache for proposer duties", z.U64("epoch", uint64(epoch)), z.I64("requested_validators_count", int64(len(vidxs))))
	defer func(t time.Time) {
		log.Debug(ctx, "dutiescache proposer - fetched cache for proposer duties", z.I64("duration_ms", time.Since(t).Milliseconds()), z.U64("epoch", uint64(epoch)), z.I64("requested_validators_count", int64(len(vidxs))))
	}(start)

	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: vidxs,
	}

	var duties []*eth2v1.ProposerDuty

	log.Debug(ctx, "dutiescache proposer - load", z.U64("epoch", uint64(epoch)))
	dutiesAny, ok := c.proposerDuties.Load(epoch)
	if !ok {
		log.Debug(ctx, "dutiescache proposer - not found cached epoch", z.U64("epoch", uint64(epoch)))
		missedCacheCount.WithLabelValues("proposer_duties").Inc()
		log.Debug(ctx, "dutiescache proposer - fetch from eth2cl", z.U64("epoch", uint64(epoch)))
		eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, opts)
		if err != nil {
			return nil, err
		}
		proposerDutiesCurrEpoch := []*eth2v1.ProposerDuty{}

		log.Debug(ctx, "dutiescache proposer - fetched from eth2cl, filter duties", z.U64("epoch", uint64(epoch)))
		for _, duty := range eth2Resp.Data {
			if duty == nil {
				return nil, errors.New("proposer duty data is nil")
			}
			d := *duty

			proposerDutiesCurrEpoch = append(proposerDutiesCurrEpoch, &d)
		}

		log.Debug(ctx, "dutiescache proposer - update cache with filtered duties", z.U64("epoch", uint64(epoch)))
		c.proposerDuties.Store(epoch, proposerDutiesCurrEpoch)

		duties = proposerDutiesCurrEpoch
	} else {
		dutiesFetched, ok := dutiesAny.([]*eth2v1.ProposerDuty)
		if !ok {
			missedCacheCount.WithLabelValues("proposer_duties").Inc()
			eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, opts)
			if err != nil {
				return nil, err
			}
			proposerDutiesCurrEpoch := []*eth2v1.ProposerDuty{}

			for _, duty := range eth2Resp.Data {
				if duty == nil {
					return nil, errors.New("proposer duty data is nil")
				}
				d := *duty

				proposerDutiesCurrEpoch = append(proposerDutiesCurrEpoch, &d)
			}

			c.proposerDuties.Store(epoch, proposerDutiesCurrEpoch)
			duties = eth2Resp.Data
		} else {
			log.Debug(ctx, "dutiescache proposer - found cached epoch", z.U64("epoch", uint64(epoch)))
			usedCacheCount.WithLabelValues("proposer_duties").Inc()
			duties = dutiesFetched
		}
	}

	log.Debug(ctx, "dutiescache proposer - finished", z.U64("epoch", uint64(epoch)))
	return duties, nil
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

	duties, ok := c.cachedAttesterDuties(ctx, epoch, vidxs)

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

	c.attesterDuties.Store(epoch, eth2Resp.Data)

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

	duties, ok := c.cachedSyncDuties(ctx, epoch, vidxs)

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

	syncDutiesCurrEpoch := []*eth2v1.SyncCommitteeDuty{}

	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return nil, errors.New("sync duty data is nil")
		}

		syncDutiesCurrEpoch = append(syncDutiesCurrEpoch, duty)
	}

	c.syncDuties.Store(epoch, syncDutiesCurrEpoch)

	return syncDutiesCurrEpoch, nil
}

// cachedProposerDuties returns the cached proposer duties and true if they are available.
func (c *DutiesCache) cachedProposerDuties(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, bool) {
	log.Debug(ctx, "dutiescache proposer - get proposer duties", z.U64("epoch", uint64(epoch)))

	dutiesAny, ok := c.proposerDuties.Load(epoch)
	if !ok {
		log.Debug(ctx, "dutiescache proposer - get proposer duties, not found cached epoch", z.U64("epoch", uint64(epoch)))
		return nil, false
	}
	duties, ok := dutiesAny.([]*eth2v1.ProposerDuty)
	if !ok {
		log.Warn(ctx, "", errors.New("dutiescache proposer - failed to parse"), z.U64("epoch", uint64(epoch)))
		return nil, false
	}

	log.Debug(ctx, "dutiescache proposer - get proposer duties, found cached epoch", z.U64("epoch", uint64(epoch)), z.Int("duties", len(duties)))
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

	log.Debug(ctx, "dutiescache proposer - get proposer duties, filtered idxs specified, returning filtered", z.U64("epoch", uint64(epoch)), z.Int("duties", len(dutiesFiltered)))

	return dutiesFiltered, true
}

// cachedAttesterDuties returns the cached attester duties and true if they are available.
func (c *DutiesCache) cachedAttesterDuties(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, bool) {
	dutiesAny, ok := c.attesterDuties.Load(epoch)
	if !ok {
		return nil, false
	}

	duties, ok := dutiesAny.([]*eth2v1.AttesterDuty)
	if !ok {
		log.Warn(ctx, "", errors.New("unable to parse attesterDuties value to attester duties during trim", z.U64("epoch", uint64(epoch)), z.Any("value", dutiesAny)))
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
func (c *DutiesCache) cachedSyncDuties(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, bool) {
	dutiesAny, ok := c.syncDuties.Load(epoch)
	if !ok {
		return nil, false
	}

	duties, ok := dutiesAny.([]*eth2v1.SyncCommitteeDuty)
	if !ok {
		log.Warn(ctx, "", errors.New("unable to parse syncDuties value to sync committee duties during trim", z.U64("epoch", uint64(epoch)), z.Any("value", dutiesAny)))
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
