// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"slices"
	"strconv"
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
	sync.RWMutex

	eth2Cl  Client
	pubkeys []eth2p0.BLSPubKey

	active   ActiveValidators
	complete CompleteValidators
}

// Trim trims the cache.
// This should be called on epoch boundary.
func (c *ValidatorCache) Trim() {
	c.Lock()
	defer c.Unlock()

	c.active = nil
	c.complete = nil
}

// activeCached returns the cached active validators and true if they are available.
func (c *ValidatorCache) activeCached() (ActiveValidators, bool) {
	c.RLock()
	defer c.RUnlock()

	return c.active, c.active != nil
}

// cached returns the cached complete validators and true if they are available.
func (c *ValidatorCache) cached() (CompleteValidators, bool) {
	c.RLock()
	defer c.RUnlock()

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
	c.Lock()
	defer c.Unlock()

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
	c.Lock()
	defer c.Unlock()

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
	sync.RWMutex

	requestedIdxs map[eth2p0.Epoch][]eth2p0.ValidatorIndex
	duties        map[eth2p0.Epoch][]eth2v1.ProposerDuty
	metadata      map[eth2p0.Epoch]map[string]any
}

// ProposerDutiesForEpoch is a map of proposer duties for specific epoch.
type ProposerDutiesForEpoch struct {
	requestedIdxs []eth2p0.ValidatorIndex
	duties        []eth2v1.ProposerDuty
	metadata      map[string]any
}

// AttesterDuties is a map of attester duties per epoch.
type AttesterDuties struct {
	sync.RWMutex

	requestedIdxs map[eth2p0.Epoch][]eth2p0.ValidatorIndex
	duties        map[eth2p0.Epoch][]eth2v1.AttesterDuty
	metadata      map[eth2p0.Epoch]map[string]any
}

// AttesterDutiesForEpoch is a map of attester duties for specific epoch.
type AttesterDutiesForEpoch struct {
	requestedIdxs []eth2p0.ValidatorIndex
	duties        []eth2v1.AttesterDuty
	metadata      map[string]any
}

// SyncDuties is a map of sync committee duties per epoch.
type SyncDuties struct {
	sync.RWMutex

	requestedIdxs map[eth2p0.Epoch][]eth2p0.ValidatorIndex
	duties        map[eth2p0.Epoch][]eth2v1.SyncCommitteeDuty
	metadata      map[eth2p0.Epoch]map[string]any
}

// SyncDutiesForEpoch is a map of sync committee duties for specific epoch.
type SyncDutiesForEpoch struct {
	requestedIdxs []eth2p0.ValidatorIndex
	duties        []eth2v1.SyncCommitteeDuty
	metadata      map[string]any
}

// ValIdxs is a slice of active validator indices.
type ValIdxs struct {
	sync.RWMutex

	valIdxs []eth2p0.ValidatorIndex
}
type ProposerDutyWithMeta struct {
	Duties   []*eth2v1.ProposerDuty
	Metadata map[string]any
}

type AttesterDutyWithMeta struct {
	Duties   []*eth2v1.AttesterDuty
	Metadata map[string]any
}

type SyncDutyWithMeta struct {
	Duties   []*eth2v1.SyncCommitteeDuty
	Metadata map[string]any
}

// CachedDutiesProvider is the interface for providing current epoch's duties.
type CachedDutiesProvider interface {
	ProposerDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error)
	AttesterDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error)
	SyncCommDutiesCache(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error)
}

// NewDutiesCache creates a new validator cache.
func NewDutiesCache(eth2Cl Client, valIdxs []eth2p0.ValidatorIndex) *DutiesCache {
	return &DutiesCache{
		eth2Cl:        eth2Cl,
		activeValIdxs: ValIdxs{valIdxs: valIdxs},

		proposerDuties: ProposerDuties{
			duties:        make(map[eth2p0.Epoch][]eth2v1.ProposerDuty),
			metadata:      make(map[eth2p0.Epoch]map[string]any),
			requestedIdxs: make(map[eth2p0.Epoch][]eth2p0.ValidatorIndex),
		},
		attesterDuties: AttesterDuties{
			duties:        make(map[eth2p0.Epoch][]eth2v1.AttesterDuty),
			metadata:      make(map[eth2p0.Epoch]map[string]any),
			requestedIdxs: make(map[eth2p0.Epoch][]eth2p0.ValidatorIndex),
		},
		syncDuties: SyncDuties{
			duties:        make(map[eth2p0.Epoch][]eth2v1.SyncCommitteeDuty),
			metadata:      make(map[eth2p0.Epoch]map[string]any),
			requestedIdxs: make(map[eth2p0.Epoch][]eth2p0.ValidatorIndex),
		},
	}
}

// DutiesCache caches active duties.
type DutiesCache struct {
	eth2Cl        Client
	activeValIdxs ValIdxs

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
		log.Debug(ctx, "Reorg occurred through epoch transition, invalidating duties cache", z.U64("reorged_back_to_epoch", uint64(epoch)))
		invalidatedCacheDueReorgCount.WithLabelValues("validators").Inc()
	} else {
		log.Debug(ctx, "Reorg occurred, but it was not through epoch transition, duties cache is not invalidated", z.U64("reorged_epoch", uint64(epoch)))
	}
}

// UpdateActiveValIndices updates the active validator indices in the cache.
func (c *DutiesCache) UpdateActiveValIndices(vidxs []eth2p0.ValidatorIndex) {
	c.activeValIdxs.Lock()
	defer c.activeValIdxs.Unlock()

	c.activeValIdxs.valIdxs = vidxs
}

// ProposerDutiesCache returns the cached proposer duties, or fetches them if not available, populating the cache with the newly fetched ones.
// nolint: dupl // The logic is very similar between proposer, attester and sync duties, but the code is not easily reusable without adding complexity, hence the duplication.
func (c *DutiesCache) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error) {
	cacheUsed := false

	defer func() {
		if cacheUsed {
			usedCacheCount.WithLabelValues("proposer_duties").Inc()
		} else {
			missedCacheCount.WithLabelValues("proposer_duties").Inc()
		}
	}()

	c.activeValIdxs.RLock()
	allActive := c.activeValIdxs.valIdxs
	c.activeValIdxs.RUnlock()

	requestVidxs := vidxs
	if len(requestVidxs) == 0 {
		requestVidxs = allActive
	}

	dutiesForEpoch, ok := c.fetchProposerDuties(epoch)
	dutiesResult := make([]*eth2v1.ProposerDuty, 0, len(vidxs))

	if ok {
		// If the request was for all validators and also all duties are already cached, skip more expensive operations.
		// This is the common case for most validator clients and Charon, which usually request duties for all active validators.
		if len(allActive) == len(requestVidxs) && len(allActive) == len(dutiesForEpoch.requestedIdxs) {
			for _, d := range dutiesForEpoch.duties {
				dutiesResult = append(dutiesResult, &d)
			}

			cacheUsed = true

			return ProposerDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		// Filter out the found duties.
		for _, d := range dutiesForEpoch.duties {
			if slices.Contains(requestVidxs, d.ValidatorIndex) {
				dutiesResult = append(dutiesResult, &d)
			}
		}

		if len(dutiesResult) > 0 {
			cacheUsed = true
		}

		// Check if all requested duties were found in the cache (= being a subset of it).
		if len(dutiesResult) == len(requestVidxs) {
			return ProposerDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		for _, duty := range dutiesForEpoch.duties {
			requestVidxs = slices.DeleteFunc(requestVidxs, func(requestVidx eth2p0.ValidatorIndex) bool {
				return requestVidx == duty.ValidatorIndex
			})
		}

		log.Debug(ctx, "Cached proposer duties do not contain all requested validator indices, fetching from beacon node...", z.Any("missing_validator_indices", requestVidxs), z.Any("requested_validator_indices", vidxs))
	}

	eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, &eth2api.ProposerDutiesOpts{Epoch: epoch, Indices: requestVidxs})
	if err != nil {
		return ProposerDutyWithMeta{}, err
	}

	dutiesDeref := make([]eth2v1.ProposerDuty, 0, len(eth2Resp.Data))
	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return ProposerDutyWithMeta{}, errors.New("proposer duty is nil")
		}

		d := *duty
		dutiesDeref = append(dutiesDeref, d)
	}

	_, ok = c.storeOrAmendProposerDuties(epoch, ProposerDutiesForEpoch{duties: dutiesDeref, metadata: eth2Resp.Metadata, requestedIdxs: requestVidxs})
	if !ok {
		log.Debug(ctx, "Failed to cache proposer duties - another routine already cached duties for this epoch, skipping", z.U64("epoch", uint64(epoch)))
	}

	dutiesResult = append(dutiesResult, eth2Resp.Data...)

	return ProposerDutyWithMeta{Duties: dutiesResult, Metadata: eth2Resp.Metadata}, nil
}

// AttesterDutiesCache returns the cached attester duties, or fetches them if not available, populating the cache with the newly fetched ones.
// nolint: dupl // The logic is very similar between proposer, attester and sync duties, but the code is not easily reusable without adding complexity, hence the duplication.
func (c *DutiesCache) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error) {
	cacheUsed := false

	defer func() {
		if cacheUsed {
			usedCacheCount.WithLabelValues("attester_duties").Inc()
		} else {
			missedCacheCount.WithLabelValues("attester_duties").Inc()
		}
	}()

	c.activeValIdxs.RLock()
	allActive := c.activeValIdxs.valIdxs
	c.activeValIdxs.RUnlock()

	requestVidxs := vidxs
	if len(requestVidxs) == 0 {
		requestVidxs = allActive
	}

	dutiesForEpoch, ok := c.fetchAttesterDuties(epoch)
	dutiesResult := make([]*eth2v1.AttesterDuty, 0, len(vidxs))

	if ok {
		// If the request was for all validators and also all duties are already cached, this is done to skip more expensive operations.
		// This is the common case for most validator clients and Charon, which usually request duties for all active validators.
		if len(allActive) == len(requestVidxs) && len(allActive) == len(dutiesForEpoch.requestedIdxs) {
			for _, d := range dutiesForEpoch.duties {
				dutiesResult = append(dutiesResult, &d)
			}

			cacheUsed = true

			return AttesterDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		// Filter out the found duties.
		for _, d := range dutiesForEpoch.duties {
			if slices.Contains(requestVidxs, d.ValidatorIndex) {
				dutiesResult = append(dutiesResult, &d)
			}
		}

		if len(dutiesResult) > 0 {
			cacheUsed = true
		}

		// Check if all requested duties were found in the cache (= being a subset of it).
		if len(dutiesResult) == len(requestVidxs) {
			return AttesterDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		for _, duty := range dutiesForEpoch.duties {
			requestVidxs = slices.DeleteFunc(requestVidxs, func(requestVidx eth2p0.ValidatorIndex) bool {
				return requestVidx == duty.ValidatorIndex
			})
		}

		log.Debug(ctx, "Cached attester duties do not contain all requested validator indices, fetching from beacon node...", z.Any("missing_validator_indices", requestVidxs), z.Any("requested_validator_indices", vidxs))
	}

	eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, &eth2api.AttesterDutiesOpts{Epoch: epoch, Indices: requestVidxs})
	if err != nil {
		return AttesterDutyWithMeta{}, err
	}

	dutiesDeref := make([]eth2v1.AttesterDuty, 0, len(eth2Resp.Data))
	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return AttesterDutyWithMeta{}, errors.New("attester duty is nil")
		}

		d := *duty
		dutiesDeref = append(dutiesDeref, d)
	}

	_, ok = c.storeOrAmendAttesterDuties(epoch, AttesterDutiesForEpoch{duties: dutiesDeref, metadata: eth2Resp.Metadata, requestedIdxs: requestVidxs})
	if !ok {
		log.Debug(ctx, "Failed to cache attester duties - another routine already cached duties for this epoch, skipping", z.U64("epoch", uint64(epoch)))
	}

	dutiesResult = append(dutiesResult, eth2Resp.Data...)

	return AttesterDutyWithMeta{Duties: dutiesResult, Metadata: eth2Resp.Metadata}, nil
}

// SyncCommDutiesCache returns the cached sync duties, or fetches them if not available, populating the cache with the newly fetched ones.
// nolint: dupl // The logic is very similar between proposer, attester and sync duties, but the code is not easily reusable without adding complexity, hence the duplication.
func (c *DutiesCache) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error) {
	cacheUsed := false

	defer func() {
		if cacheUsed {
			usedCacheCount.WithLabelValues("sync_committee_duties").Inc()
		} else {
			missedCacheCount.WithLabelValues("sync_committee_duties").Inc()
		}
	}()

	c.activeValIdxs.RLock()
	allActive := c.activeValIdxs.valIdxs
	c.activeValIdxs.RUnlock()

	requestVidxs := vidxs
	if len(requestVidxs) == 0 {
		requestVidxs = allActive
	}

	dutiesForEpoch, ok := c.fetchSyncDuties(epoch)
	dutiesResult := make([]*eth2v1.SyncCommitteeDuty, 0, len(vidxs))

	if ok {
		// If the request was for all validators and also all duties are already cached, skip more expensive operations.
		// This is the common case for most validator clients and Charon, which usually request duties for all active validators.
		if len(allActive) == len(requestVidxs) && len(allActive) == len(dutiesForEpoch.requestedIdxs) {
			for _, d := range dutiesForEpoch.duties {
				dutiesResult = append(dutiesResult, &d)
			}

			cacheUsed = true

			return SyncDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		// Filter out the found duties.
		for _, d := range dutiesForEpoch.duties {
			if slices.Contains(requestVidxs, d.ValidatorIndex) {
				dutiesResult = append(dutiesResult, &d)
			}
		}

		if len(dutiesResult) > 0 {
			cacheUsed = true
		}

		// Check if all requested duties were found in the cache (= being a subset of it).
		if len(dutiesResult) == len(requestVidxs) {
			return SyncDutyWithMeta{Duties: dutiesResult, Metadata: dutiesForEpoch.metadata}, nil
		}

		for _, duty := range dutiesForEpoch.duties {
			requestVidxs = slices.DeleteFunc(requestVidxs, func(requestVidx eth2p0.ValidatorIndex) bool {
				return requestVidx == duty.ValidatorIndex
			})
		}

		log.Debug(ctx, "Cached sync duties do not contain all requested validator indices, fetching from beacon node...", z.Any("missing_validator_indices", requestVidxs), z.Any("requested_validator_indices", vidxs))
	}

	eth2Resp, err := c.eth2Cl.SyncCommitteeDuties(ctx, &eth2api.SyncCommitteeDutiesOpts{Epoch: epoch, Indices: requestVidxs})
	if err != nil {
		return SyncDutyWithMeta{}, err
	}

	dutiesDeref := make([]eth2v1.SyncCommitteeDuty, 0, len(eth2Resp.Data))
	for _, duty := range eth2Resp.Data {
		if duty == nil {
			return SyncDutyWithMeta{}, errors.New("sync committee duty is nil")
		}

		d := *duty
		dutiesDeref = append(dutiesDeref, d)
	}

	_, ok = c.storeOrAmendSyncDuties(epoch, SyncDutiesForEpoch{duties: dutiesDeref, metadata: eth2Resp.Metadata, requestedIdxs: requestVidxs})
	if !ok {
		log.Debug(ctx, "Failed to cache sync duties - another routine already cached duties for this epoch, skipping", z.U64("epoch", uint64(epoch)))
	}

	dutiesResult = append(dutiesResult, eth2Resp.Data...)

	return SyncDutyWithMeta{Duties: dutiesResult, Metadata: eth2Resp.Metadata}, nil
}

// fetchProposerDuties returns the cached proposer duties and true if they are available.
func (c *DutiesCache) fetchProposerDuties(epoch eth2p0.Epoch) (ProposerDutiesForEpoch, bool) {
	c.proposerDuties.RLock()
	defer c.proposerDuties.RUnlock()

	duties, ok := c.proposerDuties.duties[epoch]
	if !ok {
		return ProposerDutiesForEpoch{}, false
	}

	metadata, ok := c.proposerDuties.metadata[epoch]
	if !ok {
		return ProposerDutiesForEpoch{}, false
	}

	requestedIdxs, ok := c.proposerDuties.requestedIdxs[epoch]
	if !ok {
		return ProposerDutiesForEpoch{}, false
	}

	return ProposerDutiesForEpoch{duties: duties, metadata: metadata, requestedIdxs: requestedIdxs}, true
}

// fetchAttesterDuties returns the cached attester duties and true if they are available.
func (c *DutiesCache) fetchAttesterDuties(epoch eth2p0.Epoch) (AttesterDutiesForEpoch, bool) {
	c.attesterDuties.RLock()
	defer c.attesterDuties.RUnlock()

	duties, ok := c.attesterDuties.duties[epoch]
	if !ok {
		return AttesterDutiesForEpoch{}, false
	}

	metadata, ok := c.attesterDuties.metadata[epoch]
	if !ok {
		return AttesterDutiesForEpoch{}, false
	}

	requestedIdxs, ok := c.attesterDuties.requestedIdxs[epoch]
	if !ok {
		return AttesterDutiesForEpoch{}, false
	}

	return AttesterDutiesForEpoch{duties: duties, metadata: metadata, requestedIdxs: requestedIdxs}, true
}

// fetchSyncDuties returns the cached sync duties and true if they are available.
func (c *DutiesCache) fetchSyncDuties(epoch eth2p0.Epoch) (SyncDutiesForEpoch, bool) {
	c.syncDuties.RLock()
	defer c.syncDuties.RUnlock()

	duties, ok := c.syncDuties.duties[epoch]
	if !ok {
		return SyncDutiesForEpoch{}, false
	}

	metadata, ok := c.syncDuties.metadata[epoch]
	if !ok {
		return SyncDutiesForEpoch{}, false
	}

	requestedIdxs, ok := c.syncDuties.requestedIdxs[epoch]
	if !ok {
		return SyncDutiesForEpoch{}, false
	}

	return SyncDutiesForEpoch{duties: duties, metadata: metadata, requestedIdxs: requestedIdxs}, true
}

// storeOrAmendProposerDuties stores proposer duties in the cache for the given epoch if they don't exist and false if they already exists.
func (c *DutiesCache) storeOrAmendProposerDuties(epoch eth2p0.Epoch, dutiesForEpoch ProposerDutiesForEpoch) ([]eth2v1.ProposerDuty, bool) {
	c.proposerDuties.Lock()
	defer c.proposerDuties.Unlock()

	alreadySavedDuties, ok := c.proposerDuties.duties[epoch]
	if !ok {
		c.proposerDuties.duties[epoch] = dutiesForEpoch.duties
		c.proposerDuties.metadata[epoch] = dutiesForEpoch.metadata
		c.proposerDuties.requestedIdxs[epoch] = dutiesForEpoch.requestedIdxs

		return dutiesForEpoch.duties, true
	}

	fetchedVidxs := make([]eth2p0.ValidatorIndex, 0, len(alreadySavedDuties))
	for _, d := range alreadySavedDuties {
		fetchedVidxs = append(fetchedVidxs, d.ValidatorIndex)
	}

	appended := false

	// In the scenarios where we reach this code, it's very likely that the validator client is making 1 call per validator index, hence those O(n^2) loops are not a problem.
	newlyFetchedIdxs := []eth2p0.ValidatorIndex{}

	for _, idx := range dutiesForEpoch.requestedIdxs {
		if !slices.Contains(fetchedVidxs, idx) {
			appended = true

			newlyFetchedIdxs = append(newlyFetchedIdxs, idx)
		}
	}

	c.proposerDuties.requestedIdxs[epoch] = append(c.proposerDuties.requestedIdxs[epoch], newlyFetchedIdxs...)

	newlyFetchedDuties := []eth2v1.ProposerDuty{}

	for _, idx := range newlyFetchedIdxs {
		for _, d := range dutiesForEpoch.duties {
			if d.ValidatorIndex == idx {
				newlyFetchedDuties = append(newlyFetchedDuties, d)
			}
		}
	}

	c.proposerDuties.duties[epoch] = append(c.proposerDuties.duties[epoch], newlyFetchedDuties...)

	return alreadySavedDuties, appended
}

// storeOrAmendAttesterDuties stores attester duties in the cache for the given epoch if they don't exist and false if they already exists.
func (c *DutiesCache) storeOrAmendAttesterDuties(epoch eth2p0.Epoch, dutiesForEpoch AttesterDutiesForEpoch) ([]eth2v1.AttesterDuty, bool) {
	c.attesterDuties.Lock()
	defer c.attesterDuties.Unlock()

	alreadySavedDuties, ok := c.attesterDuties.duties[epoch]
	if !ok {
		c.attesterDuties.duties[epoch] = dutiesForEpoch.duties
		c.attesterDuties.metadata[epoch] = dutiesForEpoch.metadata
		c.attesterDuties.requestedIdxs[epoch] = dutiesForEpoch.requestedIdxs

		return dutiesForEpoch.duties, true
	}

	fetchedVidxs := make([]eth2p0.ValidatorIndex, 0, len(alreadySavedDuties))
	for _, d := range alreadySavedDuties {
		fetchedVidxs = append(fetchedVidxs, d.ValidatorIndex)
	}

	appended := false

	// In the scenarios where we reach this code, it's very likely that the validator client is making 1 call per validator index, hence those O(n^2) loops are not a problem.
	newlyFetchedIdxs := []eth2p0.ValidatorIndex{}

	for _, idx := range dutiesForEpoch.requestedIdxs {
		if !slices.Contains(fetchedVidxs, idx) {
			appended = true

			newlyFetchedIdxs = append(newlyFetchedIdxs, idx)
		}
	}

	c.attesterDuties.requestedIdxs[epoch] = append(c.attesterDuties.requestedIdxs[epoch], newlyFetchedIdxs...)

	newlyFetchedDuties := []eth2v1.AttesterDuty{}

	for _, idx := range newlyFetchedIdxs {
		for _, d := range dutiesForEpoch.duties {
			if d.ValidatorIndex == idx {
				newlyFetchedDuties = append(newlyFetchedDuties, d)
			}
		}
	}

	c.attesterDuties.duties[epoch] = append(c.attesterDuties.duties[epoch], newlyFetchedDuties...)

	return alreadySavedDuties, appended
}

// storeOrAmendSyncDuties stores sync duties in the cache for the given epoch. If the epoch already exists, it amends the new duties to the existing duties.
// Returns the newly set duties and true if any new duties were added.
func (c *DutiesCache) storeOrAmendSyncDuties(epoch eth2p0.Epoch, dutiesForEpoch SyncDutiesForEpoch) ([]eth2v1.SyncCommitteeDuty, bool) {
	c.syncDuties.Lock()
	defer c.syncDuties.Unlock()

	alreadySavedDuties, ok := c.syncDuties.duties[epoch]
	if !ok {
		c.syncDuties.duties[epoch] = dutiesForEpoch.duties
		c.syncDuties.metadata[epoch] = dutiesForEpoch.metadata
		c.syncDuties.requestedIdxs[epoch] = dutiesForEpoch.requestedIdxs

		return dutiesForEpoch.duties, true
	}

	fetchedVidxs := make([]eth2p0.ValidatorIndex, 0, len(alreadySavedDuties))
	for _, d := range alreadySavedDuties {
		fetchedVidxs = append(fetchedVidxs, d.ValidatorIndex)
	}

	appended := false

	// In the scenarios where we reach this code, it's very likely that the validator client is making 1 call per validator index, hence those O(n^2) loops are not a problem.
	newlyFetchedIdxs := []eth2p0.ValidatorIndex{}

	for _, idx := range dutiesForEpoch.requestedIdxs {
		if !slices.Contains(fetchedVidxs, idx) {
			appended = true

			newlyFetchedIdxs = append(newlyFetchedIdxs, idx)
		}
	}

	c.syncDuties.requestedIdxs[epoch] = append(c.syncDuties.requestedIdxs[epoch], newlyFetchedIdxs...)

	newlyFetchedDuties := []eth2v1.SyncCommitteeDuty{}

	for _, idx := range newlyFetchedIdxs {
		for _, d := range dutiesForEpoch.duties {
			if d.ValidatorIndex == idx {
				newlyFetchedDuties = append(newlyFetchedDuties, d)
			}
		}
	}

	c.syncDuties.duties[epoch] = append(c.syncDuties.duties[epoch], newlyFetchedDuties...)

	return alreadySavedDuties, appended
}

// trimBeforeProposerDuties removes cached proposer duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeProposerDuties(epoch eth2p0.Epoch) bool {
	c.proposerDuties.Lock()
	defer c.proposerDuties.Unlock()

	ok := false

	for k := range c.proposerDuties.duties {
		if k < epoch {
			delete(c.proposerDuties.duties, k)
			delete(c.proposerDuties.metadata, k)

			ok = true
		}
	}

	return ok
}

// trimBeforeAttesterDuties removes cached attester duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeAttesterDuties(epoch eth2p0.Epoch) bool {
	c.attesterDuties.Lock()
	defer c.attesterDuties.Unlock()

	ok := false

	for k := range c.attesterDuties.duties {
		if k < epoch {
			delete(c.attesterDuties.duties, k)
			delete(c.attesterDuties.metadata, k)

			ok = true
		}
	}

	return ok
}

// trimBeforeSyncDuties removes cached sync duties before the given epoch and returns if any were removed.
func (c *DutiesCache) trimBeforeSyncDuties(epoch eth2p0.Epoch) bool {
	c.syncDuties.Lock()
	defer c.syncDuties.Unlock()

	ok := false

	for k := range c.syncDuties.duties {
		if k < epoch {
			delete(c.syncDuties.duties, k)
			delete(c.syncDuties.metadata, k)

			ok = true
		}
	}

	return ok
}

// trimAfterProposerDuties removes cached proposer duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterProposerDuties(epoch eth2p0.Epoch) bool {
	c.proposerDuties.Lock()
	defer c.proposerDuties.Unlock()

	ok := false

	for k := range c.proposerDuties.duties {
		if k > epoch {
			delete(c.proposerDuties.duties, k)
			delete(c.proposerDuties.metadata, k)

			ok = true
		}
	}

	return ok
}

// trimAfterAttesterDuties removes cached attester duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterAttesterDuties(epoch eth2p0.Epoch) bool {
	c.attesterDuties.Lock()
	defer c.attesterDuties.Unlock()

	ok := false

	for k := range c.attesterDuties.duties {
		if k > epoch {
			delete(c.attesterDuties.duties, k)
			delete(c.attesterDuties.metadata, k)

			ok = true
		}
	}

	return ok
}

// trimAfterSyncDuties removes cached sync duties after the given epoch and returns if any were removed.
func (c *DutiesCache) trimAfterSyncDuties(epoch eth2p0.Epoch) bool {
	c.syncDuties.Lock()
	defer c.syncDuties.Unlock()

	ok := false

	for k := range c.syncDuties.duties {
		if k > epoch {
			delete(c.syncDuties.duties, k)
			delete(c.syncDuties.metadata, k)

			ok = true
		}
	}

	return ok
}
