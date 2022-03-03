// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/p2p"
)

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
		})
	})

	// Nodes bind to non-ENR addresses, with only single external bootnode.
	// Discv5 will resolve peers via external node.
	t.Run("exteral_bootnode_only", func(t *testing.T) {
		external := startExtBootnode(t)

		pingCluster(t, pingTest{
			Slow:         false,
			BindENRAddrs: false,
			BootManifest: false,
			Bootnodes:    []string{external.URLv4()},
		})
	})

	// Nodes bind to non-ENR addresses, with external bootnode AS WELL AS stale ENRs.
	// Discv5 times out resolving stale ENRs, then resolves peers via external node.
	// This is slow due to discv5 internal timeouts, run with -slow.
	t.Run("external_and_stale_enrs", func(t *testing.T) {
		external := startExtBootnode(t)

		pingCluster(t, pingTest{
			Slow:         true,
			BindENRAddrs: false,
			BootManifest: true,
			Bootnodes:    []string{external.URLv4()},
		})
	})
}

type pingTest struct {
	Slow         bool
	BindENRAddrs bool
	BootManifest bool
	Bootnodes    []string
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

	const n = 3
	ctx, cancel := context.WithCancel(context.Background())
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
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:     &manifest,
				P2PKey:       p2pKeys[i],
				PingCallback: asserter.Callback(t, i),
			},
			P2P: p2p.Config{
				UDPBootnodes:    test.Bootnodes,
				UDPBootManifest: test.BootManifest,
			},
		}

		// Either bind to ENR addresses, or bind to random address resulting in stale ENRs
		if test.BindENRAddrs {
			conf.P2P.TCPAddrs = []string{tcpAddrFromENR(t, manifest.Peers[i].ENR)}
			conf.P2P.UDPAddr = udpAddrFromENR(t, manifest.Peers[i].ENR)
		} else {
			conf.P2P.TCPAddrs = []string{availableAddr(t).String()}
			conf.P2P.UDPAddr = availableAddr(t).String()
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	asserter.Await(t)
	cancel()

	require.NoError(t, eg.Wait())
}

// startExtBootnode creates a new discv5 listener and returns its local enode.
// This can be used as external bootnode for testing.
func startExtBootnode(t *testing.T) *enode.Node {
	t.Helper()

	privkey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)

	db, err := enode.OpenDB("")
	require.NoError(t, err)

	addr := availableAddr(t)

	ln := enode.NewLocalNode(db, privkey)
	ln.Set(enr.IPv4(addr.IP))
	ln.Set(enr.UDP(addr.Port))

	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)

	listener, err := discover.ListenV5(conn, ln, discover.Config{
		PrivateKey: privkey,
	})
	require.NoError(t, err)

	t.Cleanup(listener.Close)

	return ln.Node()
}

// availableAddr returns an available local tcp address.
func availableAddr(t *testing.T) *net.TCPAddr {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()

	addr, err := net.ResolveTCPAddr(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)

	return addr
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
func (a *asserter) await(t *testing.T, expect int) {
	t.Helper()

	var actual map[interface{}]bool

	ok := assert.Eventually(t, func() bool {
		actual = make(map[interface{}]bool)
		a.callbacks.Range(func(k, v interface{}) bool {
			actual[k] = true

			return true
		})

		return len(actual) >= expect
	}, a.Timeout, time.Millisecond*10)

	if !ok {
		t.Errorf("Timeout waiting for callbacks, expect=%d, actual=%d: %v", expect, len(actual), actual)
	}
}

// pingAsserter asserts that all nodes ping all other nodes.
type pingAsserter struct {
	asserter
	N        int
	Manifest app.Manifest
}

// Await waits for all nodes to ping each other or time out.
func (a *pingAsserter) Await(t *testing.T) {
	t.Helper()

	factorial := 1
	n := a.N
	for n > 1 {
		factorial *= n
		n--
	}

	a.await(t, factorial)
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
