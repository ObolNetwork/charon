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

type (
	tickerProvider  func() (<-chan time.Time, func())
	nowFunc         func() time.Time
	metricSubmitter func(peerID peer.ID, clockOffset time.Duration, version, gitHash string, startTime time.Time)
)

// New returns a new peer info protocol instance.
func New(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc,
) *PeerInfo {
	// Set own version and git hash and start time metrics.
	name := p2p.PeerName(tcpNode.ID())
	peerVersion.WithLabelValues(name, version).Set(1)
	peerGitHash.WithLabelValues(name, gitHash).Set(1)
	peerStartGauge.WithLabelValues(name).Set(float64(time.Now().Unix()))

	for i, p := range peers {
		peerIndexGauge.WithLabelValues(p2p.PeerName(p)).Set(float64(i))
	}

	tickerProvider := func() (<-chan time.Time, func()) {
		ticker := time.NewTicker(period)
		return ticker.C, ticker.Stop
	}

	return newInternal(tcpNode, peers, version, lockHash, gitHash, sendFunc, p2p.RegisterHandler,
		tickerProvider, time.Now, newMetricsSubmitter())
}

// NewForT returns a new peer info protocol instance for testing only.
func NewForT(_ *testing.T, tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	return newInternal(tcpNode, peers, version, lockHash, gitHash, sendFunc, registerHandler,
		tickerProvider, nowFunc, metricSubmitter)
}

// newInternal returns a new instance for New or NewForT.
func newInternal(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	startTime := timestamppb.New(nowFunc())

	// Register a simple handler that returns our info and ignores the request.
	registerHandler("peerinfo", tcpNode, protocolID,
		func() proto.Message { return new(pbv1.PeerInfo) },
		func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
			return &pbv1.PeerInfo{
				CharonVersion: version,
				LockHash:      lockHash,
				GitHash:       gitHash,
				SentAt:        timestamppb.New(nowFunc()),
				StartedAt:     startTime,
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
		startTime:        startTime,
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
	gitHash          string
	startTime        *timestamppb.Timestamp
	tickerProvider   tickerProvider
	metricSubmitter  metricSubmitter
	nowFunc          func() time.Time
	noSupportFilters map[peer.ID]z.Field
	lockHashFilters  map[peer.ID]z.Field
}

// Run runs the peer info protocol until the context is cancelled.
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

// sendOnce sends one peerinfo request/response pair to each peer.
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
			GitHash:       p.gitHash,
			SentAt:        timestamppb.New(now),
			StartedAt:     p.startTime,
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
			p.metricSubmitter(peerID, clockOffset, resp.CharonVersion, resp.GitHash, resp.StartedAt.AsTime())

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

// supported returns true if the peerinfo protocolID is included in the list of protocols.
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

// newMetricsSubmitter returns a prometheus metric submitter.
func newMetricsSubmitter() metricSubmitter {
	var (
		mu            sync.Mutex
		prevVersions  = make(map[string]string)
		prevGitHashes = make(map[string]string)
	)

	return func(peerID peer.ID, clockOffset time.Duration, version string, gitHash string,
		startTime time.Time,
	) {
		peerName := p2p.PeerName(peerID)

		// Limit range of possible values
		if clockOffset < -time.Hour {
			clockOffset = -time.Hour
		} else if clockOffset > time.Hour {
			clockOffset = time.Hour
		}
		peerClockOffset.WithLabelValues(peerName).Set(clockOffset.Seconds())

		if !startTime.IsZero() {
			peerStartGauge.WithLabelValues(peerName).Set(float64(startTime.Unix()))
		}

		// Limit range of possible values
		if version == "" {
			version = "unknown"
		}
		if gitHash == "" {
			gitHash = "unknown"
		}
		// TODO(corver): Validate version and githash with regex

		peerVersion.WithLabelValues(peerName, version).Set(1)
		peerGitHash.WithLabelValues(peerName, gitHash).Set(1)

		// Clear previous metrics if changed
		mu.Lock()
		defer mu.Unlock()

		if prev, ok := prevVersions[peerName]; ok && version != prev {
			peerVersion.WithLabelValues(peerName, prev).Set(0)
		}
		if prev, ok := prevGitHashes[peerName]; ok && gitHash != prev {
			peerGitHash.WithLabelValues(peerName, prev).Set(0)
		}
		prevVersions[peerName] = version
		prevGitHashes[peerName] = gitHash
	}
}
