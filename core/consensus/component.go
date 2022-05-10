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
	"io"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
)

const (
	recvBuffer = 100
	period     = time.Second
	protocolID = "/charon/consensus/1.0.0"
)

// NewComponent returns a new consensus QBFT component.
func NewComponent(ctx context.Context, tcpNode host.Host, peers []p2p.Peer, p2pKey *ecdsa.PrivateKey) *Component {
	c := &Component{
		tcpNode:   tcpNode,
		peers:     peers,
		p2pKey:    p2pKey,
		recvChans: make(map[core.Duty]chan msgImpl),
	}

	tcpNode.SetStreamHandler(protocolID, c.makeHandler(ctx))

	return c
}

type Component struct {
	tcpNode host.Host
	peers   []p2p.Peer
	p2pKey  *ecdsa.PrivateKey
	peerIdx int64
	subs    []func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error

	recvMu    sync.Mutex
	recvChans map[core.Duty]chan msgImpl
}

// Subscribe registers a callback for unsigned duty data proposals from leaders.
// Note this function is not thread safe, it should be called *before* Run or Propose.
func (c *Component) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
	c.subs = append(c.subs, fn)
}

// Propose participants in a consensus instance proposing the provided data.
// It returns on error or when the context is cancelled.
func (c *Component) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	ctx = log.WithTopic(ctx, "qbft")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	value := core.UnsignedDataSetToProto(data)
	hash, err := hashProto(value)
	if err != nil {
		return err
	}

	wrap := instanceWrap{
		component: c,
		values:    map[[32]byte]*pbv1.UnsignedDataSet{hash: value},
		recvChan:  make(chan qbft.Msg[core.Duty, [32]byte]),
	}

	go wrap.ReceiveForever(ctx, c.getRecvChan(duty))
	defer c.deleteRecvChan(duty)

	d := qbft.Definition[core.Duty, [32]byte]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(instance core.Duty, round, process int64) bool {
			mod := ((duty.Slot) + int64(duty.Type) + round) % int64(len(c.peers))
			return mod == c.peerIdx
		},

		// Decide sends consensus output to subscribes.
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			set := core.UnsignedDataSetFromProto(qcommit[0].(msgImpl).msg.Value)
			for _, sub := range c.subs {
				if err := sub(ctx, duty, set); err != nil {
					log.Warn(ctx, "Subscriber error", err)
				}
			}
		},

		// NewTimer returns a constant period timer for all rounds.
		NewTimer: func(_ int64) (<-chan time.Time, func()) {
			timer := time.NewTimer(period)
			return timer.C, func() { timer.Stop() }
		},

		// LogUponRule logs upon rules at debug level.
		LogUponRule: func(ctx context.Context, duty core.Duty, process, round int64,
			msg qbft.Msg[core.Duty, [32]byte], uponRule string,
		) {
			log.Debug(ctx, "QBFT upon rule triggered", z.Str("rule", uponRule))
		},

		// Nodes is the number of nodes.
		Nodes: len(c.peers),
	}

	t := qbft.Transport[core.Duty, [32]byte]{
		Broadcast: wrap.Broadcast,
		Receive:   wrap.recvChan,
	}

	// Run and block until context is cancelled.
	err = qbft.Run[core.Duty, [32]byte](ctx, d, t, duty, c.peerIdx, hash)
	if !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

// makeHandler returns a consensus libp2p handler.
func (c *Component) makeHandler(ctx context.Context) func(s network.Stream) {
	return func(s network.Stream) {
		defer s.Close()

		b, err := io.ReadAll(s)
		if err != nil {
			log.Error(ctx, "Failed reading stream", err)
			return
		}

		msg := new(pbv1.ConsensusMsg)
		if err := proto.Unmarshal(b, msg); err != nil {
			log.Error(ctx, "Failed unmarshalling proto", err)
			return
		}

		if msg.Msg == nil || msg.Msg.Duty == nil {
			log.Error(ctx, "Invalid consensus message", err)
			return
		}

		duty := core.DutyFromProto(msg.Msg.Duty)
		if !duty.Type.Valid() {
			log.Error(ctx, "Invalid duty type", err)
			return
		}

		impl, err := newMsgImpl(msg.Msg, msg.Justification)
		if err != nil {
			log.Error(ctx, "Create message impl", err)
			return
		}

		select {
		case c.getRecvChan(duty) <- impl:
		default:
			log.Error(ctx, "Receive buffer full", err)
			return
		}
	}
}

// getRecvChan returns a receive channel the duty.
func (c *Component) getRecvChan(duty core.Duty) chan msgImpl {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	ch, ok := c.recvChans[duty]
	if !ok {
		ch = make(chan msgImpl, recvBuffer)
		c.recvChans[duty] = ch
	}

	return ch
}

// deleteRecvChan deletes the receive channel for a duty.
func (c *Component) deleteRecvChan(duty core.Duty) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	delete(c.recvChans, duty)
}

// instanceWrap encapsulates receiving and broadcasting for a consensus instance.
type instanceWrap struct {
	component *Component
	recvChan  chan qbft.Msg[core.Duty, [32]byte]

	valueMu sync.Mutex
	values  map[[32]byte]*pbv1.UnsignedDataSet
}

func (w *instanceWrap) setValues(msg msgImpl) {
	w.valueMu.Lock()
	defer w.valueMu.Unlock()

	w.values[msg.Value()] = msg.msg.Value
	w.values[msg.PreparedValue()] = msg.msg.PreparedValue
}

func (w *instanceWrap) getValue(hash [32]byte) (*pbv1.UnsignedDataSet, error) {
	w.valueMu.Lock()
	defer w.valueMu.Unlock()

	data, ok := w.values[hash]
	if !ok {
		return nil, errors.New("unknown value")
	}

	return data, nil
}

func (*instanceWrap) waitQuorum() {
	// TODO(corver): Implement protocol to block until quorum peers are proposing this instance.
}

func (w *instanceWrap) Broadcast(ctx context.Context, typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, value [32]byte, pr int64, pv [32]byte,
	justification []qbft.Msg[core.Duty, [32]byte],
) error {
	valueHash, err := w.getValue(value)
	if err != nil {
		return err
	}
	pvHash, err := w.getValue(pv)
	if err != nil {
		return err
	}

	msg := &pbv1.QBFTMsg{
		Type:          int64(typ),
		Duty:          core.DutyToProto(duty),
		PeerIdx:       peerIdx,
		Round:         round,
		Value:         valueHash,
		PreparedRound: pr,
		PreparedValue: pvHash,
	}

	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(msgImpl)
		if !ok {
			return errors.New("invalid justification")
		}
		justMsgs = append(justMsgs, impl.msg)
	}

	impl, err := newMsgImpl(msg, justMsgs)
	if err != nil {
		return err
	}

	// First send to self.
	select {
	case <-ctx.Done():
		return nil
	case w.recvChan <- impl:
	}

	for i, p := range w.component.peers {
		if int64(i) == w.component.peerIdx {
			// Do not broadcast to self
			continue
		}

		err := send(ctx, w.component.tcpNode, p.ID, &pbv1.ConsensusMsg{Msg: msg, Justification: justMsgs})
		if err != nil {
			log.Warn(ctx, "Failed sending message", err)
		}
	}

	return nil
}

func (w *instanceWrap) ReceiveForever(ctx context.Context, recv chan msgImpl) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-recv:
			if err := validateMsg(msg); err != nil {
				log.Warn(ctx, "Dropping invalid message", err)
				continue
			}
			w.setValues(msg)

			select {
			case <-ctx.Done():
				return
			case w.recvChan <- msg:
			}
		}
	}
}

// validateMsg returns an error if the message is invalid.
func validateMsg(_ msgImpl) error {
	// TODO(corver): implement
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
