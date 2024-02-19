// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

const (
	period                  = time.Minute
	protocolID2 protocol.ID = "/charon/peerinfo/2.0.0"
)

var gitHashMatch = regexp.MustCompile("^[0-9a-f]{7}$")

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2}
}

type (
	tickerProvider  func() (<-chan time.Time, func())
	nowFunc         func() time.Time
	metricSubmitter func(peerID peer.ID, clockOffset time.Duration, version, gitHash string, startTime time.Time)
)

// New returns a new peer info protocol instance.
func New(tcpNode host.Host, peers []peer.ID, version version.SemVer, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, builderEnabled bool,
) *PeerInfo {
	// Set own version and git hash and start time metrics.
	name := p2p.PeerName(tcpNode.ID())
	peerVersion.WithLabelValues(name, version.String()).Set(1)
	peerGitHash.WithLabelValues(name, gitHash).Set(1)
	peerStartGauge.WithLabelValues(name).Set(float64(time.Now().Unix()))
	if builderEnabled {
		peerMevEnabledGauge.WithLabelValues(name).Set(1)
	} else {
		peerMevEnabledGauge.WithLabelValues(name).Set(0)
	}

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
func NewForT(_ *testing.T, tcpNode host.Host, peers []peer.ID, version version.SemVer, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	return newInternal(tcpNode, peers, version, lockHash, gitHash, sendFunc, registerHandler,
		tickerProvider, nowFunc, metricSubmitter)
}

// newInternal returns a new instance for New or NewForT.
func newInternal(tcpNode host.Host, peers []peer.ID, version version.SemVer, lockHash []byte, gitHash string,
	sendFunc p2p.SendReceiveFunc, registerHandler p2p.RegisterHandlerFunc,
	tickerProvider tickerProvider, nowFunc nowFunc, metricSubmitter metricSubmitter,
) *PeerInfo {
	startTime := timestamppb.New(nowFunc())

	// Register a simple handler that returns our info and ignores the request.
	registerHandler("peerinfo", tcpNode, protocolID2,
		func() proto.Message { return new(pbv1.PeerInfo) },
		func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
			return &pbv1.PeerInfo{
				CharonVersion: version.String(),
				LockHash:      lockHash,
				GitHash:       gitHash,
				SentAt:        timestamppb.New(nowFunc()),
				StartedAt:     startTime,
			}, true, nil
		},
	)

	// Create log filters
	lockHashFilters := make(map[peer.ID]z.Field)
	versionFilters := make(map[peer.ID]z.Field)
	for _, peerID := range peers {
		lockHashFilters[peerID] = log.Filter()
		versionFilters[peerID] = log.Filter()
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
		versionFilters:  versionFilters,
	}
}

type PeerInfo struct {
	sendFunc        p2p.SendReceiveFunc
	tcpNode         host.Host
	peers           []peer.ID
	version         version.SemVer
	lockHash        []byte
	gitHash         string
	startTime       *timestamppb.Timestamp
	tickerProvider  tickerProvider
	metricSubmitter metricSubmitter
	nowFunc         func() time.Time
	lockHashFilters map[peer.ID]z.Field
	versionFilters  map[peer.ID]z.Field
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
			CharonVersion: p.version.String(),
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
			err := p.sendFunc(ctx, p.tcpNode, peerID, req, resp, protocolID2, p2p.WithSendReceiveRTT(rttCallback))
			if err != nil {
				return // Logging handled by send func.
			} else if resp.SentAt == nil || resp.StartedAt == nil {
				log.Error(ctx, "Invalid peerinfo response", err, z.Str("peer", p2p.PeerName(peerID)))
				return
			}

			name := p2p.PeerName(peerID)

			// Validator git hash with regex.
			if !gitHashMatch.MatchString(resp.GitHash) {
				log.Warn(ctx, "Invalid peer git hash", nil, z.Str("peer", name))
				return
			}

			expectedSentAt := time.Now().Add(-rtt / 2)
			actualSentAt := resp.SentAt.AsTime()
			clockOffset := actualSentAt.Sub(expectedSentAt)

			if err := supportedPeerVersion(resp.CharonVersion, version.Supported()); err != nil {
				peerCompatibleGauge.WithLabelValues(name).Set(0) // Set to false

				// Log as error since user action required
				log.Error(ctx, "Invalid peer version", err,
					z.Str("peer", name),
					z.Str("peer_version", resp.CharonVersion),
					z.Any("supported_versions", version.Supported()),
					p.versionFilters[peerID],
				)

				return
			}

			// Set peer compatibility to true.
			peerCompatibleGauge.WithLabelValues(name).Set(1)

			p.metricSubmitter(peerID, clockOffset, resp.CharonVersion, resp.GitHash, resp.StartedAt.AsTime())

			// Log unexpected lock hash
			if !bytes.Equal(resp.LockHash, p.lockHash) {
				// TODO(corver): Think about escalating this error when we are clear
				//  on how to handle lock file migrations.
				log.Warn(ctx, "Mismatching peer lock hash", nil,
					z.Str("peer", name),
					z.Str("lock_hash", fmt.Sprintf("%#x", resp.LockHash)),
					p.lockHashFilters[peerID],
				)
			}
		}(peerID)
	}
}

// instrumentPeerVersion instruments the peer version.
func supportedPeerVersion(peerVersion string, supported []version.SemVer) error {
	peerSemVer, err := version.Parse(peerVersion)
	if err != nil {
		return errors.Wrap(err, "parse peer version")
	}

	// Assume we are compatible with peers that are newer than us.
	if version.Compare(peerSemVer, supported[0]) > 0 {
		return nil
	}

	// Check if peer minor version matches any of our supported minor versions.
	for _, supported := range supported {
		if version.Compare(peerSemVer.Minor(), supported) == 0 {
			return nil
		}
	}

	return errors.New("unsupported peer version; coordinate with operator to align versions")
}

// newMetricsSubmitter returns a prometheus metric submitter.
func newMetricsSubmitter() metricSubmitter {
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

		peerVersion.Reset(peerName)
		peerVersion.WithLabelValues(peerName, version).Set(1)
		peerGitHash.Reset(peerName)
		peerGitHash.WithLabelValues(peerName, gitHash).Set(1)
	}
}
