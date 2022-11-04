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

package app_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cmd"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/priority"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

//go:generate go test . -v -run=TestPingCluster -slow
var slow = flag.Bool("slow", false, "enable slow tests")

// TestPingCluster starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 for peer discovery.
func TestPingCluster(t *testing.T) {
	// Nodes bind to lock ENR addresses.
	// Discv5 can just use those as bootnodes.
	t.Run("bind_enrs", func(t *testing.T) {
		pingCluster(t, pingTest{
			Slow:         false,
			BootLock:     true,
			BindENRAddrs: true,
			Bootnode:     false,
		})
	})

	// Nodes bind to random localhost ports (not the lock ENRs), with only single bootnode.
	// Discv5 will resolve peers via bootnode.
	t.Run("bootnode_only", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
			BootLock:      false,
			Bootnode:      true,
		})
	})

	// Nodes bind to random 0.0.0.0 ports (but use 127.0.0.1 as external IP), with only single bootnode.
	// Discv5 will resolve peers via bootnode and external IP.
	t.Run("external_ip", func(t *testing.T) {
		pingCluster(t, pingTest{
			ExternalIP: "127.0.0.1",
			BindZeroIP: true,
			BootLock:   false,
			Bootnode:   true,
		})
	})

	// Nodes bind to 0.0.0.0 (but use localhost as external host), with only single bootnode.
	// Discv5 will resolve peers via bootnode and external host.
	t.Run("external_host", func(t *testing.T) {
		pingCluster(t, pingTest{
			ExternalHost: "localhost",
			BindZeroIP:   true,
			BootLock:     false,
			Bootnode:     true,
		})
	})

	// Nodes are not accessible (bind to random 0.0.0.0 ports and use incorrect external IP),
	// but relay via single bootnode.
	// Node discv5 will not resolve direct address, nodes will connect to bootnode,
	// and libp2p will relay via bootnode.
	t.Run("bootnode_relay", func(t *testing.T) {
		pingCluster(t, pingTest{
			BootnodeRelay: true,
			BindZeroPort:  true,
			Bootnode:      true,
			ExternalIP:    "222.222.222.222", // Random IP, so nodes are not reachable.
		})
	})

	// Nodes bind to non-ENR addresses, with single bootnode AS WELL AS stale ENRs.
	// Discv5 times out resolving stale ENRs, then resolves peers via external node.
	// This is slow due to discv5 internal timeouts, run with -slow.
	t.Run("bootnode_and_stale_enrs", func(t *testing.T) {
		pingCluster(t, pingTest{
			Slow:          true,
			BindLocalhost: true,
			BootLock:      true,
			Bootnode:      true,
		})
	})
}

type pingTest struct {
	Slow bool

	BindENRAddrs  bool
	BindLocalhost bool
	BindZeroIP    bool
	BindZeroPort  bool
	BindNoTCP     bool

	BootLock      bool
	Bootnode      bool
	BootnodeRelay bool

	ExternalIP   string
	ExternalHost string
}

func pingCluster(t *testing.T, test pingTest) {
	t.Helper()

	timeout := time.Second * 10

	if test.Slow {
		if !*slow {
			t.Skip("skipping slow test")
			return
		}
		timeout = time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	bootAddr, bootErr := startBootnode(ctx, t)
	var bootnodes []string
	if test.Bootnode {
		bootnodes = append(bootnodes, bootAddr)
	}

	const n = 3
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)
	asserter := &pingAsserter{
		asserter: asserter{
			Timeout: timeout,
		},
		N: n, Lock: lock,
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
			},
			P2P: p2p.Config{
				UDPBootnodes:  bootnodes,
				UDPBootLock:   test.BootLock,
				ExternalHost:  test.ExternalHost,
				ExternalIP:    test.ExternalIP,
				BootnodeRelay: test.BootnodeRelay,
			},
		}

		// Either bind to ENR addresses, or bind to random address resulting in stale ENRs
		if test.BindENRAddrs {
			conf.P2P.TCPAddrs = []string{tcpAddrFromENR(t, lock.Operators[i].ENR)}
			conf.P2P.UDPAddr = udpAddrFromENR(t, lock.Operators[i].ENR)
		} else if test.BindLocalhost {
			conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
			conf.P2P.UDPAddr = testutil.AvailableAddr(t).String()
		} else if test.BindZeroIP {
			addr1 := testutil.AvailableAddr(t)
			addr2 := testutil.AvailableAddr(t)
			addr1.IP = net.IPv4zero
			addr2.IP = net.IPv4zero
			conf.P2P.TCPAddrs = []string{addr1.String()}
			conf.P2P.UDPAddr = addr2.String()
		} else if test.BindZeroPort {
			conf.P2P.TCPAddrs = []string{"0.0.0.0:0"}
			conf.P2P.UDPAddr = "0.0.0.0:0"
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
		return <-bootErr
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)

	require.NoError(t, err)
}

// startBootnode starts a charon bootnode and returns its http ENR endpoint.
func startBootnode(ctx context.Context, t *testing.T) (string, <-chan error) {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t).String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.RunBootnode(ctx, cmd.BootnodeConfig{
			DataDir:  dir,
			HTTPAddr: addr,
			P2PConfig: p2p.Config{
				UDPAddr:  testutil.AvailableAddr(t).String(),
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey:    true,
			P2PRelay:      true,
			MaxResPerPeer: 8,
			MaxConns:      1024,
		})
	}()

	endpoint := "http://" + addr + "/enr"

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

// tcpAddrFromENR returns the "<ip4>:<tcp>" address stored in the ENR.
func tcpAddrFromENR(t *testing.T, record string) string {
	t.Helper()

	r, err := p2p.DecodeENR(record)
	require.NoError(t, err)

	var (
		ip   enr.IPv4
		port enr.TCP
	)

	require.NoError(t, r.Load(&ip))
	require.NoError(t, r.Load(&port))

	return fmt.Sprintf("%s:%d", net.IP(ip), port)
}

// udoAddrFromENR returns the "<ip4>:<udp>" address stored in the ENR.
func udpAddrFromENR(t *testing.T, record string) string {
	t.Helper()

	r, err := p2p.DecodeENR(record)
	require.NoError(t, err)

	var (
		ip   enr.IPv4
		port enr.UDP
	)

	require.NoError(t, r.Load(&ip))
	require.NoError(t, r.Load(&port))

	return fmt.Sprintf("%s:%d", net.IP(ip), port)
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
func (a *pingAsserter) Callback(t *testing.T, i int) func(peer.ID) {
	t.Helper()

	peerIDs, err := a.Lock.PeerIDs()
	require.NoError(t, err)

	return func(target peer.ID) {
		for j, p := range peerIDs {
			if p == target {
				a.callbacks.Store(fmt.Sprint(i, "-", j), true)
			}
		}
	}
}

func TestInfoSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	const n = 3
	lock, p2pKeys, _ := cluster.NewForT(t, 1, n, n, 0)

	var (
		eg     errgroup.Group
		result = make(chan error)
	)
	for i := 0; i < n; i++ {
		conf := app.Config{
			Log:              log.DefaultConfig(),
			Feature:          featureset.DefaultConfig(),
			SimnetBMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				PrioritiseCallback: func(ctx context.Context, duty core.Duty, results []priority.TopicResult) error {
					var err error
					if len(results) != 1 {
						err = errors.New("unexpected number of results")
					} else if results[0].Topic != "version" {
						err = errors.New("unexpected topic")
					} else {
						var actual []string
						for _, prio := range results[0].Priorities {
							actual = append(actual, prio.Priority)
						}
						if !assert.Equal(t, version.Supported(), actual) {
							err = errors.New("unexpected priorities")
						}
					}
					select {
					case <-ctx.Done():
					case result <- err:
					}

					return nil
				},
				Lock:   &lock,
				P2PKey: p2pKeys[i],
				SimnetBMockOpts: []beaconmock.Option{
					beaconmock.WithNoAttesterDuties(),
					beaconmock.WithNoProposerDuties(),
					beaconmock.WithNoSyncCommitteeDuties(),
					beaconmock.WithSlotsPerEpoch(1),
				},
			},
			P2P: p2p.Config{
				TCPAddrs:    []string{tcpAddrFromENR(t, lock.Operators[i].ENR)},
				UDPAddr:     udpAddrFromENR(t, lock.Operators[i].ENR),
				UDPBootLock: true,
			},
		}

		eg.Go(func() error {
			defer cancel()
			return app.Run(ctx, conf)
		})
	}

	eg.Go(func() error {
		defer cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-result:
			return err
		}
	})

	err := eg.Wait()
	testutil.SkipIfBindErr(t, err)

	require.NoError(t, err)
}
