// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core/hotstuff"
)

const (
	ioBufferSize = 16
)

var errInvalidReplicaID = errors.New("invalid replica id")

// Transport implementations for tests.
type transport struct {
	recvChannels  []chan *hotstuff.Msg
	replicaRecvCh chan *hotstuff.Msg
}

func newTransport(recvChannels []chan *hotstuff.Msg, replicaRecvCh chan *hotstuff.Msg) hotstuff.Transport {
	return &transport{
		recvChannels:  recvChannels,
		replicaRecvCh: replicaRecvCh,
	}
}

func (t *transport) Broadcast(ctx context.Context, msg *hotstuff.Msg) error {
	for _, ch := range t.recvChannels {
		select {
		case ch <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (t *transport) SendTo(ctx context.Context, id hotstuff.ID, msg *hotstuff.Msg) error {
	if id < 1 || int(id) > len(t.recvChannels) {
		return errInvalidReplicaID
	}

	recvCh := t.recvChannels[id.ToIndex()]

	select {
	case recvCh <- msg:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (t *transport) ReceiveCh() <-chan *hotstuff.Msg {
	return t.replicaRecvCh
}

func TestTransport(t *testing.T) {
	const nodes = 3

	ctx := context.Background()

	recvChannels := make([]chan *hotstuff.Msg, nodes)
	for i := range recvChannels {
		recvChannels[i] = make(chan *hotstuff.Msg, ioBufferSize)
	}

	transports := make([]hotstuff.Transport, nodes)
	for i := range transports {
		transports[i] = newTransport(recvChannels, recvChannels[i])
	}

	msg := &hotstuff.Msg{
		Type:  hotstuff.MsgPrepare,
		View:  3,
		Value: []byte("bcast"),
	}

	err := transports[0].Broadcast(ctx, msg)
	require.NoError(t, err)

	for n := range nodes {
		m := <-transports[n].ReceiveCh()
		require.EqualValues(t, "bcast", m.Value)

		if n > 0 {
			val := strconv.FormatInt(int64(n), 10)
			msg := &hotstuff.Msg{
				Type:  hotstuff.MsgPreCommit,
				View:  1,
				Value: []byte(val),
			}
			err := transports[n].SendTo(ctx, hotstuff.ID(1), msg)
			require.NoError(t, err)
		}
	}

	ch0 := transports[0].ReceiveCh()

	for n := 1; n < nodes; n++ {
		expect := strconv.FormatInt(int64(n), 10)
		m := <-ch0
		require.EqualValues(t, expect, m.Value)
	}

	t.Run("invalid replica id", func(t *testing.T) {
		err := transports[0].SendTo(ctx, hotstuff.ID(nodes+1), &hotstuff.Msg{})
		require.Equal(t, errInvalidReplicaID, err)
	})
}
