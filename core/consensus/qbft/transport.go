// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"context"
	"sync"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

// Broadcaster is an interface for broadcasting messages asynchronously.
type Broadcaster interface {
	Broadcast(ctx context.Context, msg *pbv1.ConsensusMsg) error
}

// Transport encapsulates receiving and broadcasting for a consensus instance/duty.
type Transport struct {
	// Immutable state
	broadcaster Broadcaster
	privkey     *k1.PrivateKey
	recvBuffer  chan qbft.Msg[core.Duty, [32]byte] // Instance inner receive buffer.
	sniffer     *sniffer

	// Mutable state
	valueMu sync.Mutex
	valueCh <-chan proto.Message    // Channel providing lazy proposed values.
	values  map[[32]byte]*anypb.Any // maps any-wrapped proposed values to their hashes
}

// NewTransport creates a new qbftTransport.
func NewTransport(broadcaster Broadcaster, privkey *k1.PrivateKey, valueCh <-chan proto.Message,
	recvBuffer chan qbft.Msg[core.Duty, [32]byte], sniffer *sniffer,
) *Transport {
	return &Transport{
		broadcaster: broadcaster,
		privkey:     privkey,
		recvBuffer:  recvBuffer,
		sniffer:     sniffer,
		valueCh:     valueCh,
		values:      make(map[[32]byte]*anypb.Any),
	}
}

// setValues caches the values and their hashes.
func (t *Transport) setValues(msg Msg) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	for k, v := range msg.Values() {
		t.values[k] = v
	}
}

// getValue returns the value by its hash.
func (t *Transport) getValue(hash [32]byte) (*anypb.Any, error) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	// First check if we have a new value.
	select {
	case value := <-t.valueCh:
		valueHash, err := HashProto(value)
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
func (t *Transport) Broadcast(ctx context.Context, typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, valueHash [32]byte, pr int64, pvHash [32]byte,
	justification []qbft.Msg[core.Duty, [32]byte],
) error {
	// Get all hashes
	var hashes [][32]byte
	hashes = append(hashes, valueHash)
	hashes = append(hashes, pvHash)
	for _, just := range justification {
		msg, ok := just.(Msg)
		if !ok {
			return errors.New("invalid justification message")
		}
		hashes = append(hashes, msg.Value())
		hashes = append(hashes, msg.PreparedValue())
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
		pvHash, values, justification, t.privkey)
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

	return t.broadcaster.Broadcast(ctx, msg.ToConsensusMsg())
}

// ProcessReceives processes received messages from the outer buffer until the context is closed.
func (t *Transport) ProcessReceives(ctx context.Context, outerBuffer chan Msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
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

// SnifferInstance returns the current sniffed consensus instance.
func (t *Transport) SnifferInstance() *pbv1.SniffedConsensusInstance {
	return t.sniffer.Instance()
}

// RecvBuffer returns the inner receive buffer.
func (t *Transport) RecvBuffer() chan qbft.Msg[core.Duty, [32]byte] {
	return t.recvBuffer
}

// createMsg returns a new message by converting the inputs into a protobuf
// and wrapping that in a msg type.
func createMsg(typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, vHash [32]byte, pr int64, pvHash [32]byte,
	values map[[32]byte]*anypb.Any, justification []qbft.Msg[core.Duty, [32]byte],
	privkey *k1.PrivateKey,
) (Msg, error) {
	pbMsg := &pbv1.QBFTMsg{
		Type:              int64(typ),
		Duty:              core.DutyToProto(duty),
		PeerIdx:           peerIdx,
		Round:             round,
		ValueHash:         vHash[:],
		PreparedRound:     pr,
		PreparedValueHash: pvHash[:],
	}

	pbMsg, err := SignMsg(pbMsg, privkey)
	if err != nil {
		return Msg{}, err
	}

	// Transform justifications into protobufs
	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(Msg)
		if !ok {
			return Msg{}, errors.New("invalid justification")
		}
		justMsgs = append(justMsgs, impl.Msg()) // Note nested justifications are ignored.
	}

	return NewMsg(pbMsg, justMsgs, values)
}
