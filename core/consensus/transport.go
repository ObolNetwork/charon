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
	"sync"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"google.golang.org/protobuf/proto"

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
	values  map[[32]byte]*pbv1.UnsignedDataSet // maps proposed values to their hashes
}

// setValues caches the values and their hashes.
func (t *transport) setValues(msg msg) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	t.values[msg.Value()] = msg.msg.Value
	t.values[msg.PreparedValue()] = msg.msg.PreparedValue
}

// getValue returns the value by its hash.
func (t *transport) getValue(hash [32]byte) (*pbv1.UnsignedDataSet, error) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	data, ok := t.values[hash]
	if !ok {
		return nil, errors.New("unknown value")
	}

	return data, nil
}

// Broadcast creates a msg and sends it to all peers (including self).
func (t *transport) Broadcast(ctx context.Context, typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, valueHash [32]byte, pr int64, pvHash [32]byte,
	justification []qbft.Msg[core.Duty, [32]byte],
) error {
	// Get the values by their hashes.
	value, err := t.getValue(valueHash)
	if err != nil {
		return err
	}
	pv, err := t.getValue(pvHash)
	if err != nil {
		return err
	}

	// Make the message
	msg, err := createMsg(typ, duty, peerIdx, round, value, pr, pv, justification)
	if err != nil {
		return err
	}

	// First send to self.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.recvBuffer <- msg:
	}

	for i, p := range t.component.peers {
		if int64(i) == t.component.peerIdx {
			// Do not broadcast to self
			continue
		}

		err := send(ctx, t.component.tcpNode, p.ID, msg.ToConsensusMsg())
		if err != nil {
			log.Warn(ctx, "Failed sending message", err)
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
			t.setValues(msg)

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
	peerIdx int64, round int64, value *pbv1.UnsignedDataSet,
	pr int64, pv *pbv1.UnsignedDataSet,
	justification []qbft.Msg[core.Duty, [32]byte],
) (msg, error) {
	pbMsg := &pbv1.QBFTMsg{
		Type:          int64(typ),
		Duty:          core.DutyToProto(duty),
		PeerIdx:       peerIdx,
		Round:         round,
		Value:         value,
		PreparedRound: pr,
		PreparedValue: pv,
	}

	// TODO(corver): Sign message.

	// Transform justifications into protobufs
	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(msg)
		if !ok {
			return msg{}, errors.New("invalid justificationProtos")
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

// send sends the protobuf message to the peer.
func send(ctx context.Context, tcpNode host.Host, id peer.ID, pb proto.Message) error {
	s, err := tcpNode.NewStream(ctx, id, protocolID)
	if err != nil {
		return errors.Wrap(err, "new stream")
	}
	defer s.Close()

	b, err := proto.Marshal(pb)
	if err != nil {
		return errors.Wrap(err, "marshal protobuf")
	}

	_, err = s.Write(b)
	if err != nil {
		return errors.Wrap(err, "write protobuf")
	}

	return nil
}
