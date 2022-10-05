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

package peerinfo

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

const period = time.Minute

var protocolID protocol.ID = "/charon/peerinfo/1.0.0"

type tickerProvider func() (<-chan time.Time, func())
type nowFunc func() time.Time

func New(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc) *PeerInfo {
	tickerProvider := func() (<-chan time.Time, func()) {
		ticker := time.NewTicker(period)
		return ticker.C, ticker.Stop
	}

	return newInternal(tcpNode, peers, version, lockHash, sendFunc, p2p.RegisterHandler,
		tickerProvider, time.Now)
}

func NewForT(_ testing.T, tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc) *PeerInfo {
	return newInternal(tcpNode, peers, version, lockHash, sendFunc, registerHandler,
		tickerProvider, nowFunc)
}

func newInternal(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc,
) *PeerInfo {
	// Register a simple handler that returns our info and ignores the request.
	registerHandler("peerinfo", tcpNode, protocolID,
		func() proto.Message { return new(pbv1.PeerInfo) },
		func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error) {
			return &pbv1.PeerInfo{
				CharonVersion: version,
				LockHash:      lockHash,
				SentAt:        timestamppb.New(nowFunc()),
			}, true, nil
		},
	)

	return &PeerInfo{
		sendFunc:       sendFunc,
		tcpNode:        tcpNode,
		peers:          peers,
		version:        version,
		lockHash:       lockHash,
		tickerProvider: tickerProvider,
		loggedLocks:    new(sync.Map),
	}
}

type PeerInfo struct {
	sendFunc       p2p.SendReceiveFunc
	tcpNode        host.Host
	peers          []peer.ID
	version        string
	lockHash       []byte
	tickerProvider tickerProvider
	loggedLocks    *sync.Map // map[peer.ID]lockHash
}

func (p *PeerInfo) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "peerinfo")

	ticks, cancel := p.tickerProvider()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticks:
			p.sendOnce(ctx, now)
		}
	}
}

func (p *PeerInfo) sendOnce(ctx context.Context, now time.Time) {
	for _, peerID := range p.peers {
		if peerID == p.tcpNode.ID() {
			continue // Do not send to self.
		}

		req := &pbv1.PeerInfo{
			CharonVersion: p.version,
			LockHash:      p.lockHash,
			SentAt:        timestamppb.New(now),
		}

		go func(peerID peer.ID) {
			resp := new(pbv1.PeerInfo)
			err := p.sendFunc(ctx, p.tcpNode, peerID, req, resp, protocol.ID(protocolID))
			if err != nil {
				return // Logging handled by send func.
			}

			rtt := time.Since(now)
			expectSentAt := now.Add(rtt / 2)
			clockOffset := resp.SentAt.AsTime().Sub(expectSentAt)

			peerName := p2p.PeerName(peerID)
			peerClockOffset.WithLabelValues(peerName).Set(clockOffset.Seconds())
			peerVersion.WithLabelValues(peerName, resp.CharonVersion).Set(1)

			// Log unexpected lock hash
			if !bytes.Equal(resp.LockHash, p.lockHash) {
				prevHash, ok := p.loggedLocks.Load(peerID)
				if !ok || !bytes.Equal(prevHash.([]byte), resp.LockHash) {
					// Only log once when we see a new lock hash
					log.Warn(ctx, "Mismatching peer lock hash", nil,
						z.Str("peer", peerName),
						z.Str("lock_hash", fmt.Sprintf("%#x", resp.LockHash)),
					)
					p.loggedLocks.Store(peerID, resp.LockHash)

					// TODO(corver): Think about escalating this error when we are clear
					//  on how to handle lock file migrations.
				}
			}
		}(peerID)
	}
}
