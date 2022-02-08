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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

// TestPingSelfBoot starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 using manifest ENRs as bootnodes.
func TestPingSelfBoot(t *testing.T) {
	const n = 3
	ctx, cancel := context.WithCancel(context.Background())

	manifest, p2pKeys, _ := cluster.NewForT(t, n, n)

	records, err := manifest.ParsedENRs()
	require.NoError(t, err)

	asserter := &pingAsserter{N: n, Manifest: manifest}

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			P2P: p2p.Config{
				TCPAddrs: []string{tcpAddrFromENR(t, records[i])}, // Use p2p address defined in each ENR
				UDPAddr:  udpAddrFromENR(t, records[i]),           // Use discv5 address defined in each ENR
			},
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:     manifest,
				P2PKey:       p2pKeys[i],
				PingCallback: asserter.Callback(t, i),
			},
		}

		eg.Go(func() error {
			return app.Run(ctx, conf)
		})
	}

	asserter.Await(t)
	cancel()

	require.NoError(t, eg.Wait())
}

// TestPingExtBoot starts a cluster of charon nodes and waits for each node to ping all the others.
// It relies on discv5 using an external bootnode and not the manifest ENRs.
func TestPingExtBoot(t *testing.T) {
	node := startExtBootnode(t)

	const n = 3
	ctx, cancel := context.WithCancel(context.Background())

	manifest, p2pKeys, _ := cluster.NewForT(t, n, n)

	asserter := &pingAsserter{N: n, Manifest: manifest}

	var eg errgroup.Group

	for i := 0; i < n; i++ {
		conf := app.Config{
			P2P: p2p.Config{
				// Use random p2p and discv5 addresses, different from ENRs
				TCPAddrs: []string{availableAddr(t).String()},
				UDPAddr:  availableAddr(t).String(),
			},
			MonitoringAddr:   availableAddr(t).String(), // Random monitoring address
			ValidatorAPIAddr: availableAddr(t).String(), // Random validatorapi address
			TestConfig: app.TestConfig{
				Manifest:      manifest,
				P2PKey:        p2pKeys[i],
				PingCallback:  asserter.Callback(t, i),
				DiscBootnodes: []*enode.Node{node}, // Use external bootnode only
			},
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

	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
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

// pingAsserter asserts that all nodes ping all other nodes.
type pingAsserter struct {
	N        int
	Manifest cluster.Manifest
	pings    sync.Map // map[string]bool
}

// Callback returns the PingCallback function for the ith node.
func (a *pingAsserter) Callback(t *testing.T, i int) func(peer.ID) {
	t.Helper()

	peers, err := a.Manifest.PeerIDs()
	require.NoError(t, err)

	return func(target peer.ID) {
		for j, p := range peers {
			if p == target {
				a.pings.Store(fmt.Sprint(i, "-", j), true)
			}
		}
	}
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

	var pings map[interface{}]bool

	ok := assert.Eventually(t, func() bool {
		pings = make(map[interface{}]bool)
		a.pings.Range(func(k, v interface{}) bool {
			pings[k] = true

			return true
		})

		return len(pings) == factorial
	}, time.Second*5, time.Millisecond*10)

	if !ok {
		t.Errorf("Timeout waiting for pings, expect=%d, actual=%d: %v", factorial, len(pings), pings)
	}
}
