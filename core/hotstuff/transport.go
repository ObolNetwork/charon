// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	IOBufferSize = 16
)

var ErrInvalidReplicaID = errors.New("invalid replica id")

type Transport[M any] interface {
	// Broadcast sends a message to all replicas, including itself.
	Broadcast(ctx context.Context, message M) error

	// SendTo sends a message to the specified replica, typically to the leader.
	SendTo(ctx context.Context, id ID, message M) error

	// ReceiveCh returns a stream of messages received by replica.
	ReceiveCh(id ID) (<-chan M, error)
}

type transport[M any] struct {
	channels map[ID]chan M
}

func NewTransport[M any](nodes uint) Transport[M] {
	channels := make(map[ID]chan M, nodes)

	for i := range nodes {
		channels[ID(i+1)] = make(chan M, IOBufferSize)
	}

	return &transport[M]{
		channels,
	}
}

func (t *transport[M]) Broadcast(ctx context.Context, message M) error {
	for _, ch := range t.channels {
		select {
		case ch <- message:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (t *transport[M]) SendTo(ctx context.Context, id ID, message M) error {
	if _, ok := t.channels[id]; !ok {
		return ErrInvalidReplicaID
	}

	select {
	case t.channels[id] <- message:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (t *transport[M]) ReceiveCh(id ID) (<-chan M, error) {
	ch, ok := t.channels[id]
	if !ok {
		return nil, ErrInvalidReplicaID
	}

	return ch, nil
}
