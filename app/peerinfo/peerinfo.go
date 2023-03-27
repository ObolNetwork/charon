// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

const (
	period = time.Minute

	protocolID1 protocol.ID = "/charon/peerinfo/1.0.0"
	protocolID2 protocol.ID = "/charon/peerinfo/2.0.0"
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2, protocolID1}
}

type (
	tickerProvider  func() (<-chan time.Time, func())
	nowFunc         func() time.Time
	metricSubmitter func(peerID peer.ID, clockOffset time.Duration, version, gitHash string, startTime time.Time)
)

// New returns a new peer info protocol instance.
func New(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc,
) (*PeerInfo, error) {
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
func NewForT(t *testing.T, tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	t.Helper()
	p, err := newInternal(tcpNode, peers, version, lockHash, gitHash, sendFunc, registerHandler,
		tickerProvider, nowFunc, metricSubmitter)
	require.NoError(t, err)

	return p
}

// newInternal returns a new instance for New or NewForT.
func newInternal(tcpNode host.Host, peers []peer.ID, version string, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) (*PeerInfo, error) {
	startTime := timestamppb.New(nowFunc())

	// Register a simple handler that returns our info and ignores the request.
	err := registerHandler("peerinfo", tcpNode, protocolID1,
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
		p2p.WithDelimitedProtocol(protocolID2),
	)
	if err != nil {
		return nil, err
	}

	// Create log filters
	lockHashFilters := make(map[peer.ID]z.Field)
	for _, peerID := range peers {
		lockHashFilters[peerID] = log.Filter()
	}

	return &PeerInfo{
		sendFunc:        sendFunc,
		tcpNode:         tcpNode,
		peers:           peers,
		version:         version,
		lockHash:        lockHash,
		startTime:       startTime,
		metricSubmitter: metricSubmitter,
		tickerProvider:  tickerProvider,
		nowFunc:         nowFunc,
		lockHashFilters: lockHashFilters,
	}, nil
}

type PeerInfo struct {
	sendFunc        p2p.SendReceiveFunc
	tcpNode         host.Host
	peers           []peer.ID
	version         string
	lockHash        []byte
	gitHash         string
	startTime       *timestamppb.Timestamp
	tickerProvider  tickerProvider
	metricSubmitter metricSubmitter
	nowFunc         func() time.Time
	lockHashFilters map[peer.ID]z.Field
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

		req := &pbv1.PeerInfo{
			CharonVersion: p.version,
			LockHash:      p.lockHash,
			GitHash:       p.gitHash,
			SentAt:        timestamppb.New(now),
			StartedAt:     p.startTime,
		}

		go func(peerID peer.ID) {
			var rtt time.Duration
			rttCallback := func(d time.Duration) {
				rtt = d
			}

			resp := new(pbv1.PeerInfo)
			err := p.sendFunc(ctx, p.tcpNode, peerID, req, resp, protocolID1,
				p2p.WithSendReceiveRTT(rttCallback), p2p.WithDelimitedProtocol(protocolID2))
			if err != nil {
				return // Logging handled by send func.
			}

			expectedSentAt := time.Now().Add(-rtt / 2)
			actualSentAt := resp.SentAt.AsTime()
			clockOffset := actualSentAt.Sub(expectedSentAt)
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
