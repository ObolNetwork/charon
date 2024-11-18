// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package utils

import (
	"time"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	RecvBufferSize = 100 // Allow buffering some initial messages when this node is late to start an instance.
)

// NewInstanceIO returns a new instanceIO.
func NewInstanceIO[TI, TO any]() *InstanceIO[TI, TO] {
	return &InstanceIO[TI, TO]{
		Participated: make(chan struct{}),
		Proposed:     make(chan struct{}),
		Running:      make(chan struct{}),
		RecvBuffer:   make(chan TO, RecvBufferSize),
		HashCh:       make(chan [32]byte, 1),
		ValueCh:      make(chan TI, 1),
		ErrCh:        make(chan error, 1),
		DecidedAtCh:  make(chan time.Time, 1),
	}
}

// InstanceIO defines the async input and output channels of a
// single consensus instance in the Component.
type InstanceIO[TI, TO any] struct {
	Participated chan struct{}  // Closed when Participate was called for this instance.
	Proposed     chan struct{}  // Closed when Propose was called for this instance.
	Running      chan struct{}  // Closed when runInstance was already called.
	RecvBuffer   chan TO        // Outer receive buffers.
	HashCh       chan [32]byte  // Async input hash channel.
	ValueCh      chan TI        // Async input value channel.
	ErrCh        chan error     // Async output error channel.
	DecidedAtCh  chan time.Time // Async output decided timestamp channel.
}

// MarkParticipated marks the instance as participated.
// It returns an error if the instance was already marked as participated.
func (io *InstanceIO[TI, TO]) MarkParticipated() error {
	select {
	case <-io.Participated:
		return errors.New("already participated")
	default:
		close(io.Participated)
	}

	return nil
}

// MarkProposed marks the instance as proposed.
// It returns an error if the instance was already marked as proposed.
func (io *InstanceIO[TI, TO]) MarkProposed() error {
	select {
	case <-io.Proposed:
		return errors.New("already proposed")
	default:
		close(io.Proposed)
	}

	return nil
}

// MaybeStart returns true if the instance wasn't running and has been started by this call,
// otherwise it returns false if the instance was started in the past and is either running now or has completed.
func (io *InstanceIO[TI, TO]) MaybeStart() bool {
	select {
	case <-io.Running:
		return false
	default:
		close(io.Running)
	}

	return true
}
