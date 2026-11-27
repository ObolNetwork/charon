// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestSupporterVersion(t *testing.T) {
	tests := []struct {
		PeerVersion       string
		SupportedVersions []version.SemVer
		ErrContains       string
	}{
		{
			PeerVersion:       "v0.1.0",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.1",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.2",
			SupportedVersions: semvers("v0.2", "v0.1"),
		},
		{
			PeerVersion:       "v0.1-rc",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.3",
			SupportedVersions: semvers("v0.2"),
			ErrContains:       "unsupported peer version",
		},
		{
			PeerVersion:       "v0.2.0",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "",
			SupportedVersions: semvers("v0.1"),
			ErrContains:       "invalid version string",
		},
	}
	for _, test := range tests {
		t.Run(test.PeerVersion, func(t *testing.T) {
			err := supportedPeerVersion(test.PeerVersion, test.SupportedVersions)
			if test.ErrContains != "" {
				require.ErrorContains(t, err, test.ErrContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPeerBuilderAPIEnabledGauge(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	lockHash := []byte("123")
	gitHash := "abc"
	peerName := p2p.PeerName(server.ID())
	peerNickname := "johndoe"

	tests := []struct {
		name           string
		builderEnabled bool
		expectedValue  int
	}{
		{"builder enabled", true, 1},
		{"builder disabled", false, 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = New(server, []peer.ID{server.ID(), client.ID()}, version.Version, lockHash, gitHash, nil, test.builderEnabled, peerNickname, func() []byte { return nil })

			expectedMetric := fmt.Sprintf(`
			# HELP app_peerinfo_builder_api_enabled Set to 1 if builder API is enabled on this peer, else 0 if disabled.
			# TYPE app_peerinfo_builder_api_enabled gauge
			app_peerinfo_builder_api_enabled{ peer = "%s" } %d
			`, peerName, test.expectedValue)

			if err := promtestutil.CollectAndCompare(peerBuilderAPIEnabledGauge, strings.NewReader(expectedMetric), "app_peerinfo_builder_api_enabled"); err != nil {
				require.NoError(t, err, "failed to collect metric")
			}
		})
	}
}

func TestDVClientVersionCheck(t *testing.T) {
	now := time.Now()
	lockHash := []byte("abcdef")

	const gitCommit = "1234567"

	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	server.Peerstore().AddAddrs(client.ID(), client.Addrs(), peerstore.PermanentAddrTTL)
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	peers := []peer.ID{client.ID(), server.ID()}

	tests := []struct {
		name            string
		dvClient        string
		peerVersion     string
		expectSubmitted bool
		expectCompat    float64
		expectDvClient  string
	}{
		{
			name:            "non-charon skips version check",
			dvClient:        "pluto",
			peerVersion:     "v0.0.1",
			expectSubmitted: true,
			expectCompat:    1,
			expectDvClient:  "pluto",
		},
		{
			name:            "empty dv_client defaults to charon and checks version",
			dvClient:        "",
			peerVersion:     "v0.0.1",
			expectSubmitted: false,
			expectCompat:    0,
			expectDvClient:  DVClientCharon,
		},
		{
			name:            "charon with supported version passes",
			dvClient:        DVClientCharon,
			peerVersion:     version.Supported()[0].String(),
			expectSubmitted: true,
			expectCompat:    1,
			expectDvClient:  DVClientCharon,
		},
		{
			name:            "charon with unsupported version fails",
			dvClient:        DVClientCharon,
			peerVersion:     "v0.0.1",
			expectSubmitted: false,
			expectCompat:    0,
			expectDvClient:  DVClientCharon,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Register a custom handler on the server with the test's dv_client and version.
			p2p.RegisterHandler("peerinfo", server, protocolID2,
				func() proto.Message { return new(pbv1.PeerInfo) },
				func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
					return &pbv1.PeerInfo{
						CharonVersion: test.peerVersion,
						LockHash:      lockHash,
						GitHash:       gitCommit,
						SentAt:        timestamppb.New(now),
						StartedAt:     timestamppb.New(now),
						DvClient:      test.dvClient,
					}, true, nil
				},
				p2p.WithReadLimit(maxPeerInfoMsgSize),
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var submitted bool

			tickProvider := func() (<-chan time.Time, func()) {
				ch := make(chan time.Time, 1)
				ch <- now

				return ch, func() {}
			}

			metricSubmitter := func(peer.ID, time.Duration, string, string, time.Time, bool, string) {
				submitted = true

				cancel()
			}

			pi := newInternal(client, peers, version.Supported()[0], lockHash, gitCommit,
				p2p.SendReceive, p2p.RegisterHandler,
				tickProvider, func() time.Time { return now }, metricSubmitter, false, "test", func() []byte { return nil })

			// Run until the single tick is processed.
			go pi.Run(ctx)

			if test.expectSubmitted {
				<-ctx.Done()
			} else {
				// Give the goroutine time to process the tick.
				time.Sleep(500 * time.Millisecond)
				cancel()
			}

			serverName := p2p.PeerName(server.ID())

			compatVal := promtestutil.ToFloat64(peerCompatibleGauge.WithLabelValues(serverName))
			require.InDelta(t, test.expectCompat, compatVal, 0)

			dvClientVal := promtestutil.ToFloat64(peerDVClientGauge.WithLabelValues(serverName, test.expectDvClient))
			require.InDelta(t, 1, dvClientVal, 0)

			require.Equal(t, test.expectSubmitted, submitted)
		})
	}
}

func TestProposerConfigHashCheck(t *testing.T) {
	now := time.Now()
	lockHash := []byte("abcdef")
	ownHash := []byte("own-proposer-config-hash")

	const gitCommit = "1234567"

	tests := []struct {
		name         string
		peerHash     []byte
		expectSeries bool
		expectValue  float64
	}{
		{
			name:         "matching hash",
			peerHash:     ownHash,
			expectSeries: true,
			expectValue:  0,
		},
		{
			name:         "mismatching hash",
			peerHash:     []byte("other-proposer-config-hash"),
			expectSeries: true,
			expectValue:  1,
		},
		{
			name:         "absent hash skips comparison",
			peerHash:     nil,
			expectSeries: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peerProposerConfigMismatchGauge.Reset()

			server := testutil.CreateHost(t, testutil.AvailableAddr(t))
			client := testutil.CreateHost(t, testutil.AvailableAddr(t))

			server.Peerstore().AddAddrs(client.ID(), client.Addrs(), peerstore.PermanentAddrTTL)
			client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

			peers := []peer.ID{client.ID(), server.ID()}

			p2p.RegisterHandler("peerinfo", server, protocolID2,
				func() proto.Message { return new(pbv1.PeerInfo) },
				func(context.Context, peer.ID, proto.Message) (proto.Message, bool, error) {
					return &pbv1.PeerInfo{
						CharonVersion:      version.Supported()[0].String(),
						LockHash:           lockHash,
						GitHash:            gitCommit,
						SentAt:             timestamppb.New(now),
						StartedAt:          timestamppb.New(now),
						DvClient:           DVClientCharon,
						ProposerConfigHash: test.peerHash,
					}, true, nil
				},
				p2p.WithReadLimit(maxPeerInfoMsgSize),
			)

			ctx := t.Context()

			tickProvider := func() (<-chan time.Time, func()) {
				ch := make(chan time.Time, 1)
				ch <- now

				return ch, func() {}
			}

			metricSubmitter := func(peer.ID, time.Duration, string, string, time.Time, bool, string) {}

			pi := newInternal(client, peers, version.Supported()[0], lockHash, gitCommit,
				p2p.SendReceive, p2p.RegisterHandler,
				tickProvider, func() time.Time { return now }, metricSubmitter, false, "test", func() []byte { return ownHash })

			go pi.Run(ctx)

			serverName := p2p.PeerName(server.ID())

			if test.expectSeries {
				require.Eventually(t, func() bool {
					if promtestutil.CollectAndCount(peerProposerConfigMismatchGauge) != 1 {
						return false
					}

					return promtestutil.ToFloat64(peerProposerConfigMismatchGauge.WithLabelValues(serverName)) == test.expectValue
				}, 5*time.Second, 50*time.Millisecond)
			} else {
				// Give the goroutine time to process the tick, no series may appear.
				time.Sleep(500 * time.Millisecond)
				require.Zero(t, promtestutil.CollectAndCount(peerProposerConfigMismatchGauge))
			}
		})
	}
}

func semvers(s ...string) []version.SemVer {
	var resp []version.SemVer

	for _, v := range s {
		sv, _ := version.Parse(v)
		resp = append(resp, sv)
	}

	return resp
}

func TestPeerInfoProposerConfigMismatch(t *testing.T) {
	now := time.Now()
	lockHash := []byte("abcdef")

	const gitCommit = "1234567"

	peerProposerConfigMismatchGauge.Reset()

	nodeA := testutil.CreateHost(t, testutil.AvailableAddr(t))
	nodeB := testutil.CreateHost(t, testutil.AvailableAddr(t))

	nodeA.Peerstore().AddAddrs(nodeB.ID(), nodeB.Addrs(), peerstore.PermanentAddrTTL)
	nodeB.Peerstore().AddAddrs(nodeA.ID(), nodeA.Addrs(), peerstore.PermanentAddrTTL)

	peers := []peer.ID{nodeA.ID(), nodeB.ID()}

	var hashB atomic.Pointer[[]byte]

	setB := func(h string) {
		b := []byte(h)
		hashB.Store(&b)
	}
	setB("rev-1")

	noopTicks := func() (<-chan time.Time, func()) { return make(chan time.Time), func() {} }
	noopSubmit := func(peer.ID, time.Duration, string, string, time.Time, bool, string) {}
	nowFunc := func() time.Time { return now }

	// Node B only serves responses.
	_ = newInternal(nodeB, peers, version.Supported()[0], lockHash, gitCommit,
		p2p.SendReceive, p2p.RegisterHandler, noopTicks, nowFunc, noopSubmit, false, "b",
		func() []byte { return *hashB.Load() })

	ticks := make(chan time.Time)
	tickProvider := func() (<-chan time.Time, func()) { return ticks, func() {} }

	piA := newInternal(nodeA, peers, version.Supported()[0], lockHash, gitCommit,
		p2p.SendReceive, p2p.RegisterHandler, tickProvider, nowFunc, noopSubmit, false, "a",
		func() []byte { return []byte("rev-1") })

	var logs syncBuffer

	log.InitConsoleForT(t, zapcore.AddSync(&logs))
	go piA.Run(t.Context())

	nameB := p2p.PeerName(nodeB.ID())
	gauge := func() float64 { return promtestutil.ToFloat64(peerProposerConfigMismatchGauge.WithLabelValues(nameB)) }

	ticks <- now

	require.Eventually(t, func() bool {
		return promtestutil.CollectAndCount(peerProposerConfigMismatchGauge) == 1 && gauge() == 0
	}, 5*time.Second, 50*time.Millisecond)

	// Node B moves to a new revision, the next tick flags the mismatch.
	setB("rev-2")

	ticks <- now

	require.Eventually(t, func() bool { return gauge() == 1 }, 5*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "proposer config") }, 5*time.Second, 50*time.Millisecond)

	// Both hashes are logged: ours and the peer's.
	require.Contains(t, logs.String(), fmt.Sprintf("%#x", []byte("rev-1")))
	require.Contains(t, logs.String(), fmt.Sprintf("%#x", []byte("rev-2")))
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, err := b.buf.Write(p)

	return n, errors.Wrap(err, "write")
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
