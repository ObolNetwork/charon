// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
)

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
	return nil, errors.New("attester duties cache is not implemented")
}

// SyncCommDutiesCache returns the cached sync duties, or fetches them if not available, populating the cache with the newly fetched ones.
func (c *DutiesCache) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	return nil, errors.New("sync committee duties cache is not implemented")
}
