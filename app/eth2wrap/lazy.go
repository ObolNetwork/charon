// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"sync"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// newLazy creates a new lazy client.
func newLazy(provider func() (Client, error)) *lazy {
	return &lazy{
		provider: provider,
	}
}

// lazy is a client that is created on demand.
type lazy struct {
	provider func() (Client, error)
	client   Client
	mu       sync.RWMutex
}

// getClient returns the client, creating it if necessary.
func (l *lazy) getClient() (Client, error) {
	// Check if the client is available.
	l.mu.RLock()
	if l.client != nil {
		l.mu.RUnlock()
		return l.client, nil
	}
	l.mu.RUnlock()

	// Else create a new client.
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check again in case another goroutine created the client.
	if l.client != nil {
		return l.client, nil
	}

	var err error
	l.client, err = l.provider()

	return l.client, err
}

func (l *lazy) Name() string {
	cl, err := l.getClient()
	if err != nil {
		return ""
	}

	return cl.Name()
}

func (l *lazy) Address() string {
	cl, err := l.getClient()
	if err != nil {
		return ""
	}

	return cl.Address()
}

func (l *lazy) AggregateBeaconCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	cl, err := l.getClient()
	if err != nil {
		return nil, err
	}

	return cl.AggregateBeaconCommitteeSelections(ctx, partialSelections)
}

func (l *lazy) AggregateSyncCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	cl, err := l.getClient()
	if err != nil {
		return nil, err
	}

	return cl.AggregateSyncCommitteeSelections(ctx, partialSelections)
}

func (l *lazy) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	cl, err := l.getClient()
	if err != nil {
		return nil, err
	}

	return cl.BlockAttestations(ctx, stateID)
}

func (l *lazy) NodePeerCount(ctx context.Context) (int, error) {
	cl, err := l.getClient()
	if err != nil {
		return 0, err
	}

	return cl.NodePeerCount(ctx)
}
