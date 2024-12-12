// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package utils

import (
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	RecvBufferSize = 100 // Allow buffering some initial messages when this node is late to start an instance.
)

// NewInstanceIO returns a new instanceIO.
func NewInstanceIO[T any]() *InstanceIO[T] {
	return &InstanceIO[T]{
		RecvBuffer:  make(chan T, RecvBufferSize),
		HashCh:      make(chan [32]byte, 1),
		ValueCh:     make(chan proto.Message, 1),
		ErrCh:       make(chan error, 1),
		DecidedAtCh: make(chan time.Time, 1),
	}
}

// InstanceIO defines the async input and output channels of a
// single consensus instance in the Component.
type InstanceIO[T any] struct {
	Participated atomic.Bool        // True when Participate was called for this instance.
	Proposed     atomic.Bool        // True when Propose was called for this instance.
	Running      atomic.Bool        // True when runInstance was already called.
	RecvBuffer   chan T             // Outer receive buffers.
	HashCh       chan [32]byte      // Async input hash channel.
	ValueCh      chan proto.Message // Async input value channel.
	ErrCh        chan error         // Async output error channel.
	DecidedAtCh  chan time.Time     // Async output decided timestamp channel.
}

// MarkParticipated marks the instance as participated.
// It returns an error if the instance was already marked as participated.
func (io *InstanceIO[T]) MarkParticipated() error {
	if !io.Participated.CompareAndSwap(false, true) {
		return errors.New("already participated")
	}

	return nil
}

// MarkProposed marks the instance as proposed.
// It returns an error if the instance was already marked as proposed.
func (io *InstanceIO[T]) MarkProposed() error {
	if !io.Proposed.CompareAndSwap(false, true) {
		return errors.New("already proposed")
	}

	return nil
}

// MaybeStart returns true if the instance wasn't running and has been started by this call,
// otherwise it returns false if the instance was started in the past and is either running now or has completed.
func (io *InstanceIO[T]) MaybeStart() bool {
	return io.Running.CompareAndSwap(false, true)
}
