// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package consensus

import (
	"context"
	"crypto/ecdsa"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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

	// Mutable state
	valueMu sync.Mutex
	values  map[[32]byte]proto.Message // maps proposed values to their hashes
}

// setValues caches the values and their hashes.
func (t *transport) setValues(msg msg) error {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	value, ok, err := msgValue(msg.msg)
	if err != nil {
		return err
	} else if ok {
		t.values[msg.Value()] = value
	}

	pv, ok, err := msgPreparedValue(msg.msg)
	if err != nil {
		return err
	} else if ok {
		t.values[msg.PreparedValue()] = pv
	}

	return nil
}

// getValue returns the value by its hash.
func (t *transport) getValue(hash [32]byte) (proto.Message, error) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

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
	// Get the values by their hashes if not zero.
	var (
		value proto.Message
		pv    proto.Message
		err   error
	)

	if valueHash != [32]byte{} {
		value, err = t.getValue(valueHash)
		if err != nil {
			return err
		}
	}

	if pvHash != [32]byte{} {
		pv, err = t.getValue(pvHash)
		if err != nil {
			return err
		}
	}

	// Make the message
	msg, err := createMsg(typ, duty, peerIdx, round, value, pr, pv, justification, t.component.privkey)
	if err != nil {
		return err
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBuffer <- msg:
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err = t.component.sender.SendAsync(ctx, t.component.tcpNode, protocolID, p.ID, msg.ToConsensusMsg())
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcessReceives processes received messages from the outer buffer until the context is closed.
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
			if err := t.setValues(msg); err != nil {
				log.Warn(ctx, "Error caching message values", err)
				continue
			}

			select {
			case <-ctx.Done():
				return
			case t.recvBuffer <- msg:
			}
		}
	}
}

// createMsg returns a new message by converting the inputs into a protobuf
// and wrapping that in a msg type.
func createMsg(typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, value proto.Message,
	pr int64, pv proto.Message,
	justification []qbft.Msg[core.Duty, [32]byte], privkey *ecdsa.PrivateKey,
) (msg, error) {
	// Convert opaque protos to anys
	var (
		vAny, pvAny       *anypb.Any
		vlegacy, pvLegacy *pbv1.UnsignedDataSet
		err               error
	)
	if value != nil {
		vAny, err = anypb.New(value)
		if err != nil {
			return msg{}, errors.Wrap(err, "new any value")
		}
		vlegacy, _ = value.(*pbv1.UnsignedDataSet)
	}
	if pv != nil {
		pvAny, err = anypb.New(pv)
		if err != nil {
			return msg{}, errors.Wrap(err, "new any value")
		}
		pvLegacy, _ = pv.(*pbv1.UnsignedDataSet)
	}

	pbMsg := &pbv1.QBFTMsg{
		Type:                int64(typ),
		Duty:                core.DutyToProto(duty),
		PeerIdx:             peerIdx,
		Round:               round,
		Value:               vAny,
		ValueLegacy:         vlegacy,
		PreparedRound:       pr,
		PreparedValue:       pvAny,
		PreparedValueLegacy: pvLegacy,
	}

	pbMsg, err = signMsg(pbMsg, privkey)
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

	return newMsg(pbMsg, justMsgs)
}

// validateMsg returns an error if the message is invalid.
func validateMsg(_ msg) error {
	// TODO(corver): implement (incl signature verification).
	return nil
}
