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

type (
	tickerProvider  func() (<-chan time.Time, func())
	nowFunc         func() time.Time
	metricSubmitter func(peerID peer.ID, clockOffset time.Duration, version string)
)

func New(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc,
) *PeerInfo {
	tickerProvider := func() (<-chan time.Time, func()) {
		ticker := time.NewTicker(period)
		return ticker.C, ticker.Stop
	}
	metricSubmitter := func(peerID peer.ID, clockOffset time.Duration, version string) {
		peerName := p2p.PeerName(peerID)
		peerClockOffset.WithLabelValues(peerName).Set(clockOffset.Seconds())
		peerVersion.WithLabelValues(peerName, version).Set(1)
	}

	return newInternal(tcpNode, peers, version, lockHash, sendFunc, p2p.RegisterHandler,
		tickerProvider, time.Now, metricSubmitter)
}

func NewForT(_ *testing.T, tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	return newInternal(tcpNode, peers, version, lockHash, sendFunc, registerHandler,
		tickerProvider, nowFunc, metricSubmitter)
}

func newInternal(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
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

	// Create log filters
	noSupportFilters := make(map[peer.ID]z.Field)
	lockHashFilters := make(map[peer.ID]z.Field)
	for _, peerID := range peers {
		noSupportFilters[peerID] = log.Filter()
		lockHashFilters[peerID] = log.Filter()
	}

	return &PeerInfo{
		sendFunc:         sendFunc,
		tcpNode:          tcpNode,
		peers:            peers,
		version:          version,
		lockHash:         lockHash,
		metricSubmitter:  metricSubmitter,
		tickerProvider:   tickerProvider,
		nowFunc:          nowFunc,
		noSupportFilters: noSupportFilters,
		lockHashFilters:  lockHashFilters,
	}
}

type PeerInfo struct {
	sendFunc         p2p.SendReceiveFunc
	tcpNode          host.Host
	peers            []peer.ID
	version          string
	lockHash         []byte
	tickerProvider   tickerProvider
	metricSubmitter  metricSubmitter
	nowFunc          func() time.Time
	noSupportFilters map[peer.ID]z.Field
	lockHashFilters  map[peer.ID]z.Field
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

		// Check if peer supports this protocol.
		if protocols, err := p.tcpNode.Peerstore().GetProtocols(peerID); err != nil || len(protocols) == 0 {
			// Ignore peer until some protocols detected
			continue
		} else if !supported(protocols) {
			log.Warn(ctx, "Non-critical peerinfo protocol not supported by peer", nil,
				z.Str("peer", p2p.PeerName(peerID)),
				p.noSupportFilters[peerID],
			)

			continue
		}

		req := &pbv1.PeerInfo{
			CharonVersion: p.version,
			LockHash:      p.lockHash,
			SentAt:        timestamppb.New(now),
		}

		go func(peerID peer.ID) {
			resp := new(pbv1.PeerInfo)
			err := p.sendFunc(ctx, p.tcpNode, peerID, req, resp, protocolID)
			if err != nil {
				return // Logging handled by send func.
			}

			rtt := p.nowFunc().Sub(now)
			expectSentAt := now.Add(rtt / 2)
			clockOffset := resp.SentAt.AsTime().Sub(expectSentAt)
			p.metricSubmitter(peerID, clockOffset, resp.CharonVersion)

			// Log unexpected lock hash
			if !bytes.Equal(resp.LockHash, p.lockHash) {
				// TODO(corver): Think about escalating this error when we are clear
				//  on how to handle lock file migrations.
				log.Warn(ctx, "Mismatching peer lock hash", nil,
					z.Str("peer", p2p.PeerName(peerID)),
					z.Str("lock_hash", fmt.Sprintf("%#x", resp.LockHash)),
					p.lockHashFilters[peerID],
				)
			}
		}(peerID)
	}
}

func supported(protocols []string) bool {
	var supported bool
	for _, p := range protocols {
		if p == string(protocolID) {
			supported = true
			break
		}
	}

	return supported
}
