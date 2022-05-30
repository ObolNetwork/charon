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

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
)

const (
	recvBuffer = 100 // Allow buffering some initial messages when this node is late to start an instance.
	period     = time.Second
	protocolID = "/charon/consensus/qbft/1.0.0"
)

// New returns a new consensus QBFT component.
func New(tcpNode host.Host, peers []p2p.Peer, p2pKey *ecdsa.PrivateKey) (*Component, error) {
	// Extract peer pubkeys.
	keys := make(map[int64]*ecdsa.PublicKey)
	for i, p := range peers {
		var pk enode.Secp256k1
		if err := p.ENR.Load(&pk); err != nil {
			return nil, errors.Wrap(err, "load pubkey")
		}
		epk := ecdsa.PublicKey(pk)
		keys[int64(i)] = &epk
	}

	c := &Component{
		tcpNode:     tcpNode,
		peers:       peers,
		privkey:     p2pKey,
		pubkeys:     keys,
		recvBuffers: make(map[core.Duty]chan msg),
	}

	// Create qbft definition (this is constant across all consensus instances)
	c.def = qbft.Definition[core.Duty, [32]byte]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(duty core.Duty, round, process int64) bool {
			mod := ((duty.Slot) + int64(duty.Type) + round) % int64(len(peers))
			return mod == process
		},

		// Decide sends consensus output to subscribers.
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			set := core.UnsignedDataSetFromProto(qcommit[0].(msg).msg.Value)
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
		Nodes: len(peers),

		// FIFOLimit caps the max buffered messages per peer.
		FIFOLimit: recvBuffer,
	}

	return c, nil
}

// Component implements core.Consensus.
type Component struct {
	// Immutable state
	tcpNode host.Host
	peers   []p2p.Peer
	pubkeys map[int64]*ecdsa.PublicKey
	privkey *ecdsa.PrivateKey
	def     qbft.Definition[core.Duty, [32]byte]
	subs    []func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error

	// Mutable state
	recvMu      sync.Mutex
	recvBuffers map[core.Duty]chan msg // Instance outer receive buffers.
}

// Subscribe registers a callback for unsigned duty data proposals from leaders.
// Note this function is not thread safe, it should be called *before* Start and Propose.
func (c *Component) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
	c.subs = append(c.subs, fn)
}

// Start registers the libp2p receive handler. This should only be called once.
func (c *Component) Start(ctx context.Context) {
	c.tcpNode.SetStreamHandler(protocolID, c.makeHandler(ctx))
}

// Propose participants in a consensus instance proposing the provided data.
// It returns on error or nil when the context is cancelled.
func (c *Component) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	ctx = log.WithTopic(ctx, "qbft")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Debug(ctx, "Starting qbft consensus instance", z.Any("duty", duty))

	// Hash the proposed data, since qbft ony supports simple comparable values.
	value := core.UnsignedDataSetToProto(data)
	hash, err := hashProto(value)
	if err != nil {
		return err
	}

	// Create a transport handles sending and receiving for this instance.
	t := transport{
		component:  c,
		values:     map[[32]byte]*pbv1.UnsignedDataSet{hash: value},
		recvBuffer: make(chan qbft.Msg[core.Duty, [32]byte]),
	}

	// Start a receiving goroutine.
	go t.ProcessReceives(ctx, c.getRecvBuffer(duty))
	defer c.deleteRecvChan(duty)

	// Create a qbft transport from the transport
	qt := qbft.Transport[core.Duty, [32]byte]{
		Broadcast: t.Broadcast,
		Receive:   t.recvBuffer,
	}

	peerIdx, err := c.getPeerIdx()
	if err != nil {
		return err
	}

	// Run the algo, blocking until the context is cancelled.
	err = qbft.Run[core.Duty, [32]byte](ctx, c.def, qt, duty, peerIdx, hash)
	if err != nil && !isContextErr(err) {
		return err // Only return non-context errors.
	}

	return nil
}

// makeHandler returns a consensus libp2p handler.
func (c *Component) makeHandler(ctx context.Context) func(s network.Stream) {
	ctx = log.WithTopic(ctx, "qbft")
	return func(s network.Stream) {
		defer s.Close()

		b, err := io.ReadAll(s)
		if err != nil {
			log.Error(ctx, "Failed reading stream", err)
			return
		}

		pbMsg := new(pbv1.ConsensusMsg)
		if err := proto.Unmarshal(b, pbMsg); err != nil {
			log.Error(ctx, "Failed unmarshalling proto", err)
			return
		}

		if pbMsg.Msg == nil || pbMsg.Msg.Duty == nil {
			log.Error(ctx, "Invalid consensus message", errors.New("nil msg"))
			return
		}

		duty := core.DutyFromProto(pbMsg.Msg.Duty)
		if !duty.Type.Valid() {
			log.Error(ctx, "Invalid duty type", errors.New("", z.Str("type", duty.Type.String())))
			return
		}

		if ok, err := verifyMsgSig(pbMsg.Msg, c.pubkeys[pbMsg.Msg.PeerIdx]); err != nil || !ok {
			log.Error(ctx, "Invalid message signature", err)
			return
		}

		for _, msg := range pbMsg.Justification {
			if ok, err := verifyMsgSig(msg, c.pubkeys[msg.PeerIdx]); err != nil || !ok {
				log.Error(ctx, "Invalid justification signature", err)
				return
			}
		}

		msg, err := newMsg(pbMsg.Msg, pbMsg.Justification)
		if err != nil {
			log.Error(ctx, "Create message pbMsg", err)
			return
		}

		select {
		case c.getRecvBuffer(duty) <- msg:
			// TODO(corver): Trim channels on duty deadline.
		default:
			log.Error(ctx, "Receive buffer full", err)
			return
		}
	}
}

// getRecvBuffer returns a receive buffer for the duty.
func (c *Component) getRecvBuffer(duty core.Duty) chan msg {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	ch, ok := c.recvBuffers[duty]
	if !ok {
		ch = make(chan msg, recvBuffer)
		c.recvBuffers[duty] = ch
	}

	return ch
}

// deleteRecvChan deletes the receive channel for the duty.
func (c *Component) deleteRecvChan(duty core.Duty) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	delete(c.recvBuffers, duty)
}

// getPeerIdx returns the local peer index.
func (c *Component) getPeerIdx() (int64, error) {
	peerIdx := int64(-1)
	for i, p := range c.peers {
		if c.tcpNode.ID() == p.ID {
			peerIdx = int64(i)
		}
	}
	if peerIdx == -1 {
		return 0, errors.New("local libp2p host not in peer list")
	}

	return peerIdx, nil
}

func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
