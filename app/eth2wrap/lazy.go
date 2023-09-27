// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/core/denebcharon"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

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
	valCache func(context.Context) (ActiveValidators, error)
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

	return cl, err
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

func (l *lazy) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.ActiveValidators(ctx)
}

func (l *lazy) SetValidatorCache(valCache func(context.Context) (ActiveValidators, error)) {
	l.clientMu.Lock()
	l.valCache = valCache
	l.clientMu.Unlock()

	if cl, ok := l.getClient(); ok {
		cl.SetValidatorCache(valCache)
	}
}

func (l *lazy) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.ProposerConfig(ctx)
}

func (l *lazy) AggregateBeaconCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.AggregateBeaconCommitteeSelections(ctx, partialSelections)
}

func (l *lazy) AggregateSyncCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.AggregateSyncCommitteeSelections(ctx, partialSelections)
}

func (l *lazy) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return nil, err
	}

	return cl.BlockAttestations(ctx, stateID)
}

func (l *lazy) NodePeerCount(ctx context.Context) (int, error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return 0, err
	}

	return cl.NodePeerCount(ctx)
}

func (l *lazy) SubmitBeaconBlock(ctx context.Context, block *denebcharon.VersionedSignedBeaconBlock) error {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitBeaconBlock(ctx, block)
}
