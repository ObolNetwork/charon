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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cmd"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -run=TestPingCluster -slow
var slow = flag.Bool("slow", false, "enable slow tests")

// TestPingCluster starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 for peer discovery.
func TestPingCluster(t *testing.T) {
	// Nodes bind to manifest ENR addresses.
	// Discv5 can just use those as bootnodes.
	t.Run("bind_enrs", func(t *testing.T) {
		pingCluster(t, pingTest{
			Slow:         false,
			BootManifest: true,
			BindENRAddrs: true,
			Bootnode:     false,
		})
	})

	// Nodes bind to random localhost ports (not the manifest ENRs), with only single bootnode.
	// Discv5 will resolve peers via bootnode.
	t.Run("bootnode_only", func(t *testing.T) {
		pingCluster(t, pingTest{
			BindLocalhost: true,
			BootManifest:  false,
			Bootnode:      true,
		})
	})

	// Nodes bind to random 0.0.0.0 ports (but use 127.0.0.1 as external IP), with only single bootnode.
	// Discv5 will resolve peers via bootnode and external IP.
	t.Run("external_ip", func(t *testing.T) {

		pingCluster(t, pingTest{
			ExternalIP:   "127.0.0.1",
			BindZero:     true,
			BootManifest: false,
			Bootnode:     true,
		})
	})

	// Nodes bind to random 0.0.0.0 ports (but use localhost as external host), with only single bootnode.
	// Discv5 will resolve peers via bootnode and external host.
	t.Run("external_host", func(t *testing.T) {
		pingCluster(t, pingTest{
			ExternalHost: "localhost",
			BindZero:     true,
			BootManifest: false,
			Bootnode:     true,
		})
	})

	// Nodes bind to non-ENR addresses, with single bootnode AS WELL AS stale ENRs.
	// Discv5 times out resolving stale ENRs, then resolves peers via external node.
	// This is slow due to discv5 internal timeouts, run with -slow.
	t.Run("bootnode_and_stale_enrs", func(t *testing.T) {
		pingCluster(t, pingTest{
			Slow:          true,
			BindLocalhost: true,
			BootManifest:  true,
			Bootnode:      true,
		})
	})
}

type pingTest struct {
	Slow          bool
	BindENRAddrs  bool
	BindLocalhost bool
	BindZero      bool
	BootManifest  bool
	Bootnode      bool
	ExternalIP    string
	ExternalHost  string
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
		bootnodes = append(bootnodes, "http://"+bootAddr+"/enr")
	}

	const n = 3
	manifest, p2pKeys, _ := app.NewClusterForT(t, 1, n, n, 0)
	asserter := &pingAsserter{
		asserter: asserter{
			Timeout: timeout,
		},
		N: n, Manifest: manifest,
	}

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			Log:              log.DefaultConfig(),
			SimnetBMock:      true,
			MonitoringAddr:   testutil.AvailableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: testutil.AvailableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:     &manifest,
				P2PKey:       p2pKeys[i],
				PingCallback: asserter.Callback(t, i),
			},
			P2P: p2p.Config{
				UDPBootnodes:    bootnodes,
				UDPBootManifest: test.BootManifest,
				ExteranlHost:    test.ExternalHost,
				ExternalIP:      test.ExternalIP,
			},
		}

		// Either bind to ENR addresses, or bind to random address resulting in stale ENRs
		if test.BindENRAddrs {
			conf.P2P.TCPAddrs = []string{tcpAddrFromENR(t, manifest.Peers[i].ENR)}
			conf.P2P.UDPAddr = udpAddrFromENR(t, manifest.Peers[i].ENR)
		} else if test.BindLocalhost {
			conf.P2P.TCPAddrs = []string{testutil.AvailableAddr(t).String()}
			conf.P2P.UDPAddr = testutil.AvailableAddr(t).String()
		} else if test.BindZero {
			addr1 := testutil.AvailableAddr(t)
			addr2 := testutil.AvailableAddr(t)
			addr1.IP = net.IPv4zero
			addr2.IP = net.IPv4zero
			conf.P2P.TCPAddrs = []string{addr1.String()}
			conf.P2P.UDPAddr = addr2.String()
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

// startBootnode starts a charon bootnode and returns its http address.
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
			P2PRelay: true,
			P2PConfig: p2p.Config{
				UDPAddr:  testutil.AvailableAddr(t).String(),
				TCPAddrs: []string{testutil.AvailableAddr(t).String()},
			},
			LogConfig: log.Config{
				Level:  "error",
				Format: "console",
			},
			AutoP2PKey: true,
		})
	}()

	return addr, errChan
}

// tcpAddrFromENR returns the "<ip4>:<tcp>" address stored in the ENR.
func tcpAddrFromENR(t *testing.T, record enr.Record) string {
	t.Helper()

	var (
		ip   enr.IPv4
		port enr.TCP
	)

	require.NoError(t, record.Load(&ip))
	require.NoError(t, record.Load(&port))

	return fmt.Sprintf("%s:%d", net.IP(ip), port)
}

// udoAddrFromENR returns the "<ip4>:<udp>" address stored in the ENR.
func udpAddrFromENR(t *testing.T, record enr.Record) string {
	t.Helper()

	var (
		ip   enr.IPv4
		port enr.UDP
	)

	require.NoError(t, record.Load(&ip))
	require.NoError(t, record.Load(&port))

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
	N        int
	Manifest app.Manifest
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

	return func(target peer.ID) {
		for j, p := range a.Manifest.PeerIDs() {
			if p == target {
				a.callbacks.Store(fmt.Sprint(i, "-", j), true)
			}
		}
	}
}
