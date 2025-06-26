// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package integration_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

// TestPingCluster starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 for peer discovery.
func TestPingCluster(t *testing.T) {
	skipIfDisabled(t)

	// Nodes bind to random localhost ports,
	// use relay,
	// then upgrade to direct connections.
	t.Run("relay_discovery_local", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
		})
	})

	// Nodes bind to random localhost ports,
	// use relay, filters external dns multiaddrs only,
	// then upgrade to direct connections.
	t.Run("relay_discovery_externalhost", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
			ExternalHost:  "localhost",
			AddrFilter:    "dns",
		})
	})

	// Nodes bind to random localhost ports,
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

	ctx, cancel := context.WithCancel(context.Background())

	relayAddr := startRelay(ctx, t)

	const n = 3

	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, seed, random)
	asserter := &pingAsserter{
		asserter: asserter{
			Timeout: time.Second * 10,
		},
		N:    n,
		Lock: lock,
	}

	var eg errgroup.Group

	for i := range n {
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
			err := app.Run(peerCtx(ctx, i), conf)
			t.Logf("Peer %d exitted: err=%v", i, err)
			cancel()

			return err
		})
	}

	eg.Go(func() error {
		defer cancel()
		return asserter.Await(ctx, t)
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

	return func(target peer.ID, p2pNode host.Host) {
		var foundDirect bool
		for _, conn := range p2pNode.Network().ConnsToPeer(target) {
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
