// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd/relay"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/p2p"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(tblsv2.Herumi{})
	os.Exit(m.Run())
}

// TestPingCluster starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 for peer discovery.
func TestPingCluster(t *testing.T) {
	// Nodes bind to random locahost ports,
	// use relay,
	// then upgrade to direct connections.
	t.Run("relay_discovery_local", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
		})
	})

	// Nodes bind to random locahost ports,
	// use relay, filters external dns multiaddrs only,
	// then upgrade to direct connections.
	t.Run("relay_discovery_externalhost", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
			ExternalHost:  "localhost",
			AddrFilter:    "dns",
		})
	})

	// Nodes bind to random locahost ports,
	// use relay, includes incorrect external IP, but should include local address,
	// then upgrade to direct connections.
	t.Run("relay_incorrect_externalhost", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
			ExternalIP:    "222.222.222.22",
		})
	})
}

type pingTest struct {
	BindLocalhost bool
	BindZeroIP    bool
	ExternalIP    string
	ExternalHost  string
	AddrFilter    string // Regexp filter for advertised libp2p addresses.
}

func pingCluster(t *testing.T, test pingTest) {
	t.Helper()

	timeout := time.Second * 10

	ctx, cancel := context.WithCancel(context.Background())

	relayAddr, relayErr := startRelay(ctx, t)

	const n = 3

	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)
	asserter := &pingAsserter{
		asserter: asserter{
			Timeout: timeout,
		},
		N:    n,
		Lock: lock,
	}

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				TestPingConfig: p2p.TestPingConfig{
					Callback:   asserter.Callback(t, i),
					MaxBackoff: time.Second,
				},
				Lock:   &lock,
				P2PKey: p2pKeys[i],
				SimnetBMockOpts: []beaconmock.Option{
					beaconmock.WithNoAttesterDuties(),
					beaconmock.WithNoProposerDuties(),
					beaconmock.WithNoSyncCommitteeDuties(),
				},
				LibP2POpts: []libp2p.Option{newAddrFactoryFilter(test.AddrFilter)},
			},
			P2P: p2p.Config{
				Relays:       []string{relayAddr},
				ExternalHost: test.ExternalHost,
				ExternalIP:   test.ExternalIP,
			},
		}

		if test.BindLocalhost { // Bind to random address
			conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
		} else if test.BindZeroIP {
			addr1 := testutil.AvailableAddr(t)
			addr1.IP = net.IPv4zero
			conf.P2P.TCPAddrs = []string{addr1.String()}
		} else {
			require.Fail(t, "no bind flag set")
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	eg.Go(func() error {
		defer cancel()
		return asserter.Await(ctx, t)
	})

	eg.Go(func() error {
		defer cancel()
		return <-relayErr
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	testutil.RequireNoError(t, err)
}

// newAddrFactoryFilter returns a libp2p option that filters any advertised addresses based on the provided regexp string.
func newAddrFactoryFilter(filterStr string) libp2p.Option {
	filter := regexp.MustCompile(filterStr)

	return func(cfg *libp2p.Config) error {
		cached := cfg.AddrsFactory
		cfg.AddrsFactory = func(addrs []ma.Multiaddr) []ma.Multiaddr {
			var match []ma.Multiaddr
			for _, addr := range cached(addrs) {
				if filterStr == "" || filter.MatchString(addr.String()) {
					match = append(match, addr)
				}
			}

			return match
		}

		return nil
	}
}

// startRelay starts a charon relay and returns its http multiaddr endpoint.
func startRelay(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir := t.TempDir()

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- relay.Run(ctx, relay.Config{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey:    true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
	}()

	endpoint := "http://" + addr

	// Wait for bootnode to become available.
	for ctx.Err() == nil {
		_, err := http.Get(endpoint)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	return endpoint, errChan
}

// asserter provides an abstract callback asserter.
type asserter struct {
	Timeout   time.Duration
	callbacks sync.Map // map[string]bool
}

// Await waits for all nodes to ping each other or time out.
func (a *asserter) await(ctx context.Context, t *testing.T, expect int) error {
	t.Helper()

	var actual map[interface{}]bool

	ok := assert.Eventually(t, func() bool {
		if ctx.Err() != nil {
			return true
		}
		actual = make(map[interface{}]bool)
		a.callbacks.Range(func(k, v interface{}) bool {
			actual[k] = true

			return true
		})

		return len(actual) >= expect
	}, a.Timeout, time.Millisecond*10)

	if ctx.Err() != nil {
		return context.Canceled
	}

	if !ok {
		return errors.New(fmt.Sprintf("Timeout waiting for callbacks, expect=%d, actual=%d: %v", expect, len(actual), actual))
	}

	return nil
}

// pingAsserter asserts that all nodes ping all other nodes.
type pingAsserter struct {
	asserter
	N    int
	Lock cluster.Lock
}

// Await waits for all nodes to ping each other or time out.
func (a *pingAsserter) Await(ctx context.Context, t *testing.T) error {
	t.Helper()

	factorial := 1
	n := a.N
	for n > 1 {
		factorial *= n
		n--
	}

	return a.await(ctx, t, factorial)
}

// Callback returns the PingCallback function for the ith node.
func (a *pingAsserter) Callback(t *testing.T, i int) func(peer.ID, host.Host) {
	t.Helper()

	peerIDs, err := a.Lock.PeerIDs()
	require.NoError(t, err)

	return func(target peer.ID, tcpNode host.Host) {
		var foundDirect bool
		for _, conn := range tcpNode.Network().ConnsToPeer(target) {
			directConn := !p2p.IsRelayAddr(conn.RemoteMultiaddr())
			if !directConn {
				require.NoError(t, conn.Close()) // Close relay connections so direct connections are established.
			} else {
				foundDirect = true
			}
		}

		if !foundDirect {
			return
		}

		for j, p := range peerIDs {
			if p == target {
				a.callbacks.Store(fmt.Sprint(i, "-", j), true)
			}
		}
	}
}

func TestInfoSync(t *testing.T) {
	featureset.EnableForT(t, featureset.Priority)

	ctx, cancel := context.WithCancel(context.Background())

	const n = 3
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)

	asserter := &priorityAsserter{
		asserter: asserter{Timeout: time.Second * 10},
		N:        n,
	}

	var tcpNodesLock sync.Mutex
	var tcpNodes []host.Host

	// Hard code peer addresses and protocols
	tcpNodeCallback := func(tcpNode host.Host) {
		tcpNodesLock.Lock()
		defer tcpNodesLock.Unlock()

		for _, other := range tcpNodes {
			other.Peerstore().AddAddrs(tcpNode.ID(), tcpNode.Addrs(), peerstore.PermanentAddrTTL)
			err := other.Peerstore().AddProtocols(tcpNode.ID(), priority.Protocols()...)
			require.NoError(t, err)

			tcpNode.Peerstore().AddAddrs(other.ID(), other.Addrs(), peerstore.PermanentAddrTTL)
			err = tcpNode.Peerstore().AddProtocols(other.ID(), priority.Protocols()...)
			require.NoError(t, err)
		}
		tcpNodes = append(tcpNodes, tcpNode)
	}

	var eg errgroup.Group
	for i := 0; i < n; i++ {
		i := i // Copy iteration variable
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				PrioritiseCallback: asserter.Callback(t, i),
				Lock:               &lock,
				P2PKey:             p2pKeys[i],
				TCPNodeCallback:    tcpNodeCallback,
				SimnetBMockOpts: []beaconmock.Option{
					beaconmock.WithNoAttesterDuties(),
					beaconmock.WithNoProposerDuties(),
					beaconmock.WithNoSyncCommitteeDuties(),
					beaconmock.WithSlotsPerEpoch(1),
				},
			},
			P2P: p2p.Config{
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	eg.Go(func() error {
		defer cancel()
		return asserter.Await(ctx, t)
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
}

// priorityAsserter asserts that all nodes resolved the same priorities.
type priorityAsserter struct {
	asserter
	N int
}

// Await waits for all nodes to ping each other or time out.
func (a *priorityAsserter) Await(ctx context.Context, t *testing.T) error {
	t.Helper()
	return a.await(ctx, t, a.N)
}

// Callback returns the PingCallback function for the ith node.
func (a *priorityAsserter) Callback(t *testing.T, i int) func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
	t.Helper()

	return func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
		expect := map[string]string{
			"version":  fmt.Sprint(version.Supported()),
			"protocol": fmt.Sprint(app.Protocols()),
			"proposal": fmt.Sprint(app.ProposalTypes(false, false)),
		}

		if !assert.Len(t, results, len(expect)) {
			return errors.New("unexpected number of results")
		}

		for _, result := range results {
			if len(result.Priorities) == 0 {
				// Some but not all peers participated, ignore this result.
				return nil
			}

			if !assert.Equal(t, expect[result.Topic], fmt.Sprint(result.PrioritiesOnly())) {
				return errors.New("unexpected priorities")
			}
		}

		a.callbacks.Store(fmt.Sprint(i), true)

		return nil
	}
}
