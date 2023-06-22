// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

// transport encapsulates receiving and broadcasting for a consensus instance/duty.
type transport struct {
	// Immutable state
	component  *Component
	recvBuffer chan qbft.Msg[core.Duty, [32]byte] // Instance inner receive buffer.
	sniffer    *sniffer

	// Mutable state
	valueMu sync.Mutex
	valueCh <-chan proto.Message    // Channel providing lazy proposed values.
	values  map[[32]byte]*anypb.Any // maps any-wrapped proposed values to their hashes
}

// setValues caches the values and their hashes.
func (t *transport) setValues(msg msg) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	for k, v := range msg.values {
		t.values[k] = v
	}
}

// getValue returns the value by its hash.
func (t *transport) getValue(hash [32]byte) (*anypb.Any, error) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	// First check if we have a new value.
	select {
	case value := <-t.valueCh:
		valueHash, err := hashProto(value)
		if err != nil {
			return nil, err
		}

		anyValue, err := anypb.New(value)
		if err != nil {
			return nil, errors.Wrap(err, "wrap any value")
		}

		t.values[valueHash] = anyValue
	default:
		// No new values
	}

	pb, ok := t.values[hash]
	if !ok {
		return nil, errors.New("unknown value")
	}

	return pb, nil
}

// Broadcast creates a msg and sends it to all peers (including self).
func (t *transport) Broadcast(ctx context.Context, typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, valueHash [32]byte, pr int64, pvHash [32]byte,
	justification []qbft.Msg[core.Duty, [32]byte],
) error {
	// Get all hashes
	var hashes [][32]byte
	hashes = append(hashes, valueHash)
	hashes = append(hashes, pvHash)
	for _, just := range justification {
		msg, ok := just.(msg)
		if !ok {
			return errors.New("invalid justification message")
		}
		hashes = append(hashes, msg.valueHash)
		hashes = append(hashes, msg.preparedValueHash)
	}

	// Get values by their hashes if not zero.
	values := make(map[[32]byte]*anypb.Any)
	for _, hash := range hashes {
		if hash == [32]byte{} || values[hash] != nil {
			continue
		}

		value, err := t.getValue(hash)
		if err != nil {
			return err
		}

		values[hash] = value
	}

	// Make the message
	msg, err := createMsg(typ, duty, peerIdx, round, valueHash, pr,
		pvHash, values, justification, t.component.privkey)
	if err != nil {
		return err
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBuffer <- msg:
			t.sniffer.Add(msg.ToConsensusMsg())
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err = t.component.sender.SendAsync(ctx, t.component.tcpNode, protocolID2, p.ID, msg.ToConsensusMsg())
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcessReceives processes received messages from the outer buffer until the context is closed.
//

func (t *transport) ProcessReceives(ctx context.Context, outerBuffer chan msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			if err := validateMsg(msg); err != nil {
				log.Warn(ctx, "Dropping invalid message", err)
				continue
			}

			t.setValues(msg)

			select {
			case <-ctx.Done():
				return
			case t.recvBuffer <- msg:
				t.sniffer.Add(msg.ToConsensusMsg())
			}
		}
	}
}

// createMsg returns a new message by converting the inputs into a protobuf
// and wrapping that in a msg type.
func createMsg(typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, vHash [32]byte, pr int64, pvHash [32]byte,
	values map[[32]byte]*anypb.Any, justification []qbft.Msg[core.Duty, [32]byte],
	privkey *k1.PrivateKey,
) (msg, error) {
	pbMsg := &pbv1.QBFTMsg{
		Type:              int64(typ),
		Duty:              core.DutyToProto(duty),
		PeerIdx:           peerIdx,
		Round:             round,
		ValueHash:         vHash[:],
		PreparedRound:     pr,
		PreparedValueHash: pvHash[:],
	}

	pbMsg, err := signMsg(pbMsg, privkey)
	if err != nil {
		return msg{}, err
	}

	// Transform justifications into protobufs
	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(msg)
		if !ok {
			return msg{}, errors.New("invalid justification")
		}
		justMsgs = append(justMsgs, impl.msg) // Note nested justifications are ignored.
	}

	return newMsg(pbMsg, justMsgs, values)
}

// validateMsg returns an error if the message is invalid.
func validateMsg(_ msg) error {
	// TODO(corver): implement (incl signature verification).
	return nil
}

// newSniffer returns a new sniffer.
func newSniffer(nodes, peerIdx int64) *sniffer {
	return &sniffer{
		nodes:     nodes,
		peerIdx:   peerIdx,
		startedAt: time.Now(),
	}
}

// sniffer buffers consensus messages.
type sniffer struct {
	nodes     int64
	peerIdx   int64
	startedAt time.Time

	mu   sync.Mutex
	msgs []*pbv1.SniffedConsensusMsg
}

// Add adds a message to the sniffer buffer.
func (c *sniffer) Add(msg *pbv1.ConsensusMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgs = append(c.msgs, &pbv1.SniffedConsensusMsg{
		Timestamp: timestamppb.Now(),
		Msg:       msg,
	})
}

// Instance returns the buffered messages as an instance.
func (c *sniffer) Instance() *pbv1.SniffedConsensusInstance {
	c.mu.Lock()
	defer c.mu.Unlock()

	return &pbv1.SniffedConsensusInstance{
		Nodes:     c.nodes,
		PeerIdx:   c.peerIdx,
		StartedAt: timestamppb.New(c.startedAt),
		Msgs:      c.msgs,
	}
}
