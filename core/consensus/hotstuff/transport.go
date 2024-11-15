// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	hs "github.com/obolnetwork/charon/core/hotstuff"
	"github.com/obolnetwork/charon/p2p"
)

// transport implements hotstuff.Transport.
type transport struct {
	tcpNode host.Host
	sender  *p2p.Sender
	peers   []p2p.Peer
	recvCh  chan *hs.Msg
}

var _ hs.Transport = (*transport)(nil)

const (
	msgBufferSize = 16
)

func newTransport(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer) *transport {
	return &transport{
		tcpNode: tcpNode,
		sender:  sender,
		peers:   peers,
		recvCh:  make(chan *hs.Msg, msgBufferSize),
	}
}

func (t *transport) Broadcast(ctx context.Context, msg *hs.Msg) error {
	protoMsg := msg.ToProto()

	for _, peer := range t.peers {
		if t.tcpNode.ID() == peer.ID {
			select {
			case t.recvCh <- msg:
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			if err := t.sender.SendAsync(ctx, t.tcpNode, protocols.HotStuffv1ProtocolID, peer.ID, protoMsg); err != nil {
				return errors.Wrap(err, "failed to send message")
			}
		}
	}

	return nil
}

func (t *transport) SendTo(ctx context.Context, id hs.ID, msg *hs.Msg) error {
	if id < 1 || int(id) > len(t.peers) {
		return errors.New("invalid peer ID")
	}

	peer := t.peers[id.ToIndex()]
	if t.tcpNode.ID() == peer.ID {
		select {
		case t.recvCh <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		protoMsg := msg.ToProto()
		if err := t.sender.SendAsync(ctx, t.tcpNode, protocols.HotStuffv1ProtocolID, peer.ID, protoMsg); err != nil {
			return errors.Wrap(err, "failed to send message")
		}
	}

	return nil
}

func (t *transport) ReceiveCh() <-chan *hs.Msg {
	return t.recvCh
}

func (t *transport) ProcessReceives(ctx context.Context, outerBuffer chan *hs.Msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			select {
			case <-ctx.Done():
				return
			case t.recvCh <- msg:
			}
		}
	}
}
