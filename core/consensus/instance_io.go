// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	recvBuffer = 100 // Allow buffering some initial messages when this node is late to start an instance.
)

// newInstanceIO returns a new instanceIO.
func newInstanceIO[T any]() instanceIO[T] {
	return instanceIO[T]{
		participated: make(chan struct{}),
		proposed:     make(chan struct{}),
		running:      make(chan struct{}),
		recvBuffer:   make(chan T, recvBuffer),
		hashCh:       make(chan [32]byte, 1),
		valueCh:      make(chan proto.Message, 1),
		errCh:        make(chan error, 1),
		decidedAtCh:  make(chan time.Time, 1),
	}
}

// instanceIO defines the async input and output channels of a
// single consensus instance in the Component.
type instanceIO[T any] struct {
	participated chan struct{}      // Closed when Participate was called for this instance.
	proposed     chan struct{}      // Closed when Propose was called for this instance.
	running      chan struct{}      // Closed when runInstance was already called.
	recvBuffer   chan T             // Outer receive buffers.
	hashCh       chan [32]byte      // Async input hash channel.
	valueCh      chan proto.Message // Async input value channel.
	errCh        chan error         // Async output error channel.
	decidedAtCh  chan time.Time     // Async output decided timestamp channel.
}

// MarkParticipated marks the instance as participated.
// It returns an error if the instance was already marked as participated.
func (io instanceIO[T]) MarkParticipated() error {
	select {
	case <-io.participated:
		return errors.New("already participated")
	default:
		close(io.participated)
	}

	return nil
}

// MarkProposed marks the instance as proposed.
// It returns an error if the instance was already marked as proposed.
func (io instanceIO[T]) MarkProposed() error {
	select {
	case <-io.proposed:
		return errors.New("already proposed")
	default:
		close(io.proposed)
	}

	return nil
}

// MaybeStart returns true if the instance wasn't running and has been started by this call,
// otherwise it returns false if the instance was started in the past and is either running now or has completed.
func (io instanceIO[T]) MaybeStart() bool {
	select {
	case <-io.running:
		return false
	default:
		close(io.running)
	}

	return true
}
