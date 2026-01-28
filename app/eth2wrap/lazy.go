// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

//go:generate mockery --name=Client --output=mocks --outpkg=mocks --case=underscore

// NewLazyForT creates a new lazy client for testing.
func NewLazyForT(client Client) Client {
	return &lazy{
		provider: func(context.Context) (Client, error) {
			return client, nil
		},
		client: client,
	}
}

// newLazy creates a new lazy client.
func newLazy(provider func(context.Context) (Client, error)) *lazy {
	return &lazy{
		provider: provider,
	}
}

// lazy is a client that is created on demand.
type lazy struct {
	providerMu sync.Mutex
	provider   func(context.Context) (Client, error)

	clientMu            sync.RWMutex
	client              Client
	valCache            func(context.Context) (ActiveValidators, CompleteValidators, error)
	proposerDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	attesterDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	syncCommDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
}

// getClient returns the client and true if it is available.
func (l *lazy) getClient() (Client, bool) {
	l.clientMu.RLock()
	defer l.clientMu.RUnlock()

	return l.client, l.client != nil
}

// setClient sets the client.
func (l *lazy) setClient(client Client) {
	l.clientMu.Lock()
	defer l.clientMu.Unlock()

	if l.valCache != nil {
		client.SetValidatorCache(l.valCache)
	}

	l.client = client
}

// getOrCreateClient returns the client, creating it if necessary.
func (l *lazy) getOrCreateClient(ctx context.Context) (Client, error) {
	// Check if the client is available.
	if cl, ok := l.getClient(); ok {
		return cl, nil
	}

	// Try until we get the provider lock or the context is cancelled.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for !l.providerMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// Try again
		}
	}
	defer l.providerMu.Unlock()

	// Check again in case another goroutine created the client.
	if cl, ok := l.getClient(); ok {
		return cl, nil
	}

	cl, err := l.provider(ctx)
	if err != nil {
		return nil, err
	}

	l.setClient(cl)

	return cl, nil
}

func (l *lazy) SetForkVersion(forkVersion [4]byte) {
	cl, ok := l.getClient()
	if !ok {
		return
	}

	cl.SetForkVersion(forkVersion)
}

func (l *lazy) Name() string {
	cl, ok := l.getClient()
	if !ok {
		return ""
	}

	return cl.Name()
}

func (l *lazy) Address() string {
	cl, ok := l.getClient()
	if !ok {
		return ""
	}

	return cl.Address()
}

// ClientForAddress returns a scoped client that queries only the specified address.
func (l *lazy) ClientForAddress(addr string) Client {
	cl, ok := l.getClient()
	if !ok {
		return l
	}

	return cl.ClientForAddress(addr)
}

func (l *lazy) Headers() map[string]string {
	cl, ok := l.getClient()
	if !ok {
		return nil
	}

	return cl.Headers()
}

func (l *lazy) IsActive() bool {
	cl, ok := l.getClient()
	if !ok {
		return false
	}

	return cl.IsActive()
}

func (l *lazy) IsSynced() bool {
	cl, ok := l.getClient()
	if !ok {
		return false
	}

	return cl.IsSynced()
}

func (l *lazy) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.ActiveValidators(ctx)
}

func (l *lazy) CompleteValidators(ctx context.Context) (CompleteValidators, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.CompleteValidators(ctx)
}

func (l *lazy) SetValidatorCache(valCache func(context.Context) (ActiveValidators, CompleteValidators, error)) {
	l.clientMu.Lock()
	l.valCache = valCache
	l.clientMu.Unlock()

	if cl, ok := l.getClient(); ok {
		cl.SetValidatorCache(valCache)
	}
}

func (l *lazy) SetDutiesCache(
	proposerDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error),
	attesterDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error),
	syncCommDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error),
) {
	l.clientMu.Lock()
	l.proposerDutiesCache = proposerDutiesCache
	l.attesterDutiesCache = attesterDutiesCache
	l.syncCommDutiesCache = syncCommDutiesCache
	l.clientMu.Unlock()

	if cl, ok := l.getClient(); ok {
		cl.SetDutiesCache(l.proposerDutiesCache, l.attesterDutiesCache, l.syncCommDutiesCache)
	}
}

func (l *lazy) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.ProposerDutiesCache(ctx, epoch, vidxs)
}

func (l *lazy) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.AttesterDutiesCache(ctx, epoch, vidxs)
}

func (l *lazy) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.SyncCommDutiesCache(ctx, epoch, vidxs)
}

func (l *lazy) UpdateCacheIndices(ctx context.Context, idxs []eth2p0.ValidatorIndex) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return
	}

	cl.UpdateCacheIndices(ctx, idxs)
}

func (l *lazy) NodeIdentity(ctx context.Context) (*NodeIdentity, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.NodeIdentity(ctx)
}