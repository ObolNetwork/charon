// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
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

func newTransport(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer) *transport {
	return &transport{
		tcpNode: tcpNode,
		sender:  sender,
		peers:   peers,
		recvCh:  make(chan *hs.Msg),
	}
}

func (t *transport) Broadcast(ctx context.Context, msg *hs.Msg) error {
	protoMsg := msgToProto(msg)

	for _, peer := range t.peers {
		if err := t.sender.SendAsync(ctx, t.tcpNode, protocols.HotStuffv1ProtocolID, peer.ID, protoMsg); err != nil {
			return errors.Wrap(err, "failed to send message")
		}
	}

	return nil
}

func (t *transport) SendTo(ctx context.Context, id hs.ID, msg *hs.Msg) error {
	if id < 1 || int(id) > len(t.peers) {
		return errors.New("invalid peer ID")
	}

	peer := t.peers[id-1]
	protoMsg := msgToProto(msg)
	if err := t.sender.SendAsync(ctx, t.tcpNode, protocols.HotStuffv1ProtocolID, peer.ID, protoMsg); err != nil {
		return errors.Wrap(err, "failed to send message")
	}

	return nil
}

func (t *transport) ReceiveCh() <-chan *hs.Msg {
	return t.recvCh
}

func (t *transport) HandleReceivedMsg(ctx context.Context, protoMsg *pbv1.HotStuffMsg) error {
	msg := protoToMsg(protoMsg)

	select {
	case t.recvCh <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func msgToProto(msg *hs.Msg) *pbv1.HotStuffMsg {
	return &pbv1.HotStuffMsg{
		Type:      uint64(msg.Type),
		View:      uint64(msg.View),
		Value:     msg.Value,
		ValueHash: msg.ValueHash[:],
		Vote:      msg.Vote,
		Signature: msg.Signature,
		Qc: func() *pbv1.HotStuffQC {
			if msg.Justify != nil {
				return &pbv1.HotStuffQC{
					Type:       uint64(msg.Justify.Type),
					View:       uint64(msg.Justify.View),
					ValueHash:  msg.Justify.ValueHash[:],
					Signatures: msg.Justify.Signatures,
				}
			}

			return nil
		}(),
	}
}

func protoToMsg(protoMsg *pbv1.HotStuffMsg) *hs.Msg {
	return &hs.Msg{
		Type:      hs.MsgType(protoMsg.GetType()),
		View:      hs.View(protoMsg.GetView()),
		Value:     protoMsg.GetValue(),
		ValueHash: fromProtoHash(protoMsg.GetValueHash()),
		Vote:      protoMsg.GetVote(),
		Signature: protoMsg.GetSignature(),
		Justify: func() *hs.QC {
			if protoMsg.GetQc() != nil {
				return &hs.QC{
					Type:       hs.MsgType(protoMsg.GetQc().GetType()),
					View:       hs.View(protoMsg.GetQc().GetView()),
					ValueHash:  fromProtoHash(protoMsg.GetQc().GetValueHash()),
					Signatures: protoMsg.GetQc().GetSignatures(),
				}
			}

			return nil
		}(),
	}
}

func fromProtoHash(protoHash []byte) hs.Hash {
	var hash hs.Hash
	copy(hash[:], protoHash)

	return hash
}
