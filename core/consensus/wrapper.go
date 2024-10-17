// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/core"
)

type consensusWrapper struct {
	lock sync.RWMutex
	impl core.Consensus
}

var _ core.Consensus = (*consensusWrapper)(nil)

// newConsensusWrapper wraps a core.Consensus implementation.
func newConsensusWrapper(impl core.Consensus) *consensusWrapper {
	return &consensusWrapper{
		impl: impl,
	}
}

// SetImpl sets the core.Consensus implementation.
func (w *consensusWrapper) SetImpl(impl core.Consensus) {
	w.lock.Lock()
	defer w.lock.Unlock()

	w.impl = impl
}

func (w *consensusWrapper) ProtocolID() protocol.ID {
	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.impl.ProtocolID()
}

func (w *consensusWrapper) Start(ctx context.Context) {
	w.lock.RLock()
	defer w.lock.RUnlock()

	w.impl.Start(ctx)
}

func (w *consensusWrapper) Participate(ctx context.Context, duty core.Duty) error {
	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.impl.Participate(ctx, duty)
}

func (w *consensusWrapper) Propose(ctx context.Context, duty core.Duty, dataSet core.UnsignedDataSet) error {
	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.impl.Propose(ctx, duty, dataSet)
}

func (w *consensusWrapper) Subscribe(fn func(context.Context, core.Duty, core.UnsignedDataSet) error) {
	w.lock.RLock()
	defer w.lock.RUnlock()

	w.impl.Subscribe(fn)
}
