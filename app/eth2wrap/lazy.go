// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"
	"time"
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

	clientMu sync.RWMutex
	client   Client
	valCache func(context.Context) (ActiveValidators, CompleteValidators, error)
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
	for !l.providerMu.TryLock() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		time.Sleep(time.Millisecond) // Don't spin.
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
