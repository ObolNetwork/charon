// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// ActiveValidators is a map of active validator indices to pubkeys.
type ActiveValidators map[eth2p0.ValidatorIndex]eth2p0.BLSPubKey

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

// ActiveValidatorsProvider is the interface for providing current epoch's cached active validator
// identity information.
type ActiveValidatorsProvider interface {
	ActiveValidators(context.Context) (ActiveValidators, error)
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

	mu     sync.RWMutex
	active ActiveValidators
}

// Trim trims the cache.
// This should be called on epoch boundary.
func (c *ValidatorCache) Trim() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.active = nil
}

// cached returns the cached validators and true if they are available.
func (c *ValidatorCache) cached() (ActiveValidators, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.active, c.active != nil
}

// Get returns the cached active validators, or fetches them if not available populating the cache.
func (c *ValidatorCache) Get(ctx context.Context) (ActiveValidators, error) {
	if cached, ok := c.cached(); ok {
		return cached, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check again in case another goroutine updated the cache while we were waiting for the lock.
	if c.active != nil {
		return c.active, nil
	}

	vals, err := c.eth2Cl.ValidatorsByPubKey(ctx, "head", c.pubkeys)
	if err != nil {
		return nil, err
	}

	resp := make(ActiveValidators)
	for _, val := range vals {
		if val == nil || val.Validator == nil {
			return nil, errors.New("validator data cannot be nil")
		}

		if !val.Status.IsActive() {
			continue
		}

		resp[val.Index] = val.Validator.PublicKey
	}

	c.active = resp

	return resp, nil
}
