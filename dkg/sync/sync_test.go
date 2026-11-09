// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sync_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/testutil"
)

func TestSyncProtocol(t *testing.T) {
	versions := make(map[int]version.SemVer)
	nicknames := make(map[int]string)

	for i := range 5 {
		versions[i] = version.Version
		nicknames[i] = fmt.Sprintf("node%d", i)
	}

	t.Run("2", func(t *testing.T) {
		testCluster(t, 2, versions, "", nicknames)
	})

	t.Run("3", func(t *testing.T) {
		testCluster(t, 3, versions, "", nicknames)
	})

	t.Run("5", func(t *testing.T) {
		testCluster(t, 5, versions, "", nicknames)
	})

	t.Run("invalid version", func(t *testing.T) {
		testCluster(t, 2,
			map[int]version.SemVer{
				0: semver(t, "v0.1"),
				1: semver(t, "v0.2"),
				2: semver(t, "v0.3"),
				3: semver(t, "v0.4"),
			},
			"mismatching charon version; expect=", nicknames)
	})
}

// TestSyncRestartRejected verifies that a peer which restarts mid-ceremony (a fresh
// client reporting step 0 after the server recorded a higher step) is rejected fast
// with an actionable error on both sides, instead of reconnect-looping forever.
func TestSyncRestartRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	hash := testutil.RandomBytes32()

	nodeA, keyA := newTCPNode(t, 0)
	nodeB, _ := newTCPNode(t, 1)

	serverB := sync.NewServer(nodeB, 1, hash, version.Version)
	serverB.Start(log.WithTopic(ctx, "serverB"))

	err := nodeA.Connect(ctx, peer.AddrInfo{ID: nodeB.ID(), Addrs: nodeB.Addrs()})
	require.NoError(t, err)

	hashSigA, err := keyA.Sign(hash)
	require.NoError(t, err)

	// First client instance from node A, advanced to step 1 (as after the initial
	// DKG step sync barrier).
	client1Ctx, client1Cancel := context.WithCancel(ctx)
	defer client1Cancel()

	client1 := sync.NewClient(nodeA, nodeB.ID(), hashSigA, version.Version, "nodeA", sync.WithPeriod(time.Millisecond*50))
	client1.SetStep(1)

	go func() {
		_ = client1.Run(log.WithTopic(client1Ctx, "client1"))
	}()

	require.NoError(t, serverB.AwaitAllConnected(ctx))
	require.NoError(t, serverB.AwaitAllAtStep(ctx, 1))

	// Simulate a process restart of node A: kill the first instance and start a
	// fresh client which reports step 0.
	client1Cancel()

	client2 := sync.NewClient(nodeA, nodeB.ID(), hashSigA, version.Version, "nodeA", sync.WithPeriod(time.Millisecond*50))
	errCh := make(chan error, 1)

	go func() {
		errCh <- client2.Run(log.WithTopic(ctx, "client2"))
	}()

	select {
	case err := <-errCh:
		require.Error(t, err)
		require.ErrorContains(t, err, "restart the ceremony together")
	case <-time.After(10 * time.Second):
		t.Fatal("restarted client did not fail fast, expected rejection by the server")
	}

	// The server records the fatal condition so the ceremony can be aborted locally.
	require.Error(t, serverB.Err())
	require.ErrorContains(t, serverB.Err(), "restart the ceremony together")
}

// TestServerExactCountUnchanged verifies that without WithMinConnected the server
// still requires every peer, including via AwaitMinConnected.
func TestServerExactCountUnchanged(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	hash := testutil.RandomBytes32()

	server, _ := newTCPNode(t, 0)
	nodeA, keyA := newTCPNode(t, 1)
	nodeB, keyB := newTCPNode(t, 2)

	s := sync.NewServer(server, 2, hash, version.Version)
	s.Start(ctx)

	startClient(ctx, t, nodeA, keyA, server, hash)

	awaitCtx, awaitCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer awaitCancel()

	require.ErrorIs(t, s.AwaitMinConnected(awaitCtx), context.DeadlineExceeded)

	startClient(ctx, t, nodeB, keyB, server, hash)

	require.NoError(t, s.AwaitMinConnected(ctx))
	require.NoError(t, s.AwaitAllConnected(ctx))
	require.ElementsMatch(t, []peer.ID{nodeA.ID(), nodeB.ID()}, s.Connected())
}

// TestServerMinConnectedFreeze verifies the minimum participant mode: three of four nodes
// proceed once frozen, and a late fourth node is rejected without failing the ceremony.
func TestServerMinConnectedFreeze(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		n       = 4
		present = 3
	)

	hash := testutil.RandomBytes32()

	var (
		nodes   []host.Host
		keys    []libp2pcrypto.PrivKey
		servers []*sync.Server
		clients []*sync.Client
	)

	for i := range n {
		node, key := newTCPNode(t, int64(i))
		nodes = append(nodes, node)
		keys = append(keys, key)
	}

	for i := range present {
		server := sync.NewServer(nodes[i], n-1, hash, version.Version, sync.WithMinConnected(present-1))
		server.Start(log.WithTopic(ctx, fmt.Sprintf("server%d", i)))
		servers = append(servers, server)
	}

	for i := range present {
		for j := range present {
			if i == j {
				continue
			}

			clients = append(clients, startClient(ctx, t, nodes[i], keys[i], nodes[j], hash))
		}
	}

	for i, server := range servers {
		require.NoError(t, server.AwaitMinConnected(ctx))

		var others []peer.ID

		for j := range present {
			if i != j {
				others = append(others, nodes[j].ID())
			}
		}

		require.ElementsMatch(t, others, server.Connected())
		require.Empty(t, server.NotAtStep(1))

		server.Freeze(others)
		require.ElementsMatch(t, others, server.NotAtStep(1))
	}

	for i := range 3 {
		assertAllAtStep(ctx, t, servers, i)

		for _, client := range clients {
			client.SetStep(i + 1)
		}
	}

	// A late fourth node is told explicitly that the ceremony started without it.
	hashSig, err := keys[3].Sign(hash)
	require.NoError(t, err)

	require.NoError(t, nodes[3].Connect(ctx, peer.AddrInfo{ID: nodes[0].ID(), Addrs: nodes[0].Addrs()}))

	late := sync.NewClient(nodes[3], nodes[0].ID(), hashSig, version.Version, "late", sync.WithPeriod(50*time.Millisecond))
	err = late.Run(ctx)
	require.ErrorContains(t, err, "ceremony already in progress, you were not part of it")
	require.NoError(t, servers[0].Err())

	for _, client := range clients {
		require.NoError(t, client.Shutdown(ctx))
	}

	for _, server := range servers {
		require.NoError(t, server.AwaitAllShutdown(ctx))
		require.NoError(t, server.Err())
		require.Empty(t, server.NotShutdown())
	}
}

// startClient connects node to server and runs a sync client against it in the background.
func startClient(ctx context.Context, t *testing.T, node host.Host, key libp2pcrypto.PrivKey, server host.Host, hash []byte) *sync.Client {
	t.Helper()

	require.NoError(t, node.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}))

	hashSig, err := key.Sign(hash)
	require.NoError(t, err)

	client := sync.NewClient(node, server.ID(), hashSig, version.Version, "", sync.WithPeriod(50*time.Millisecond))

	go func() {
		_ = client.Run(ctx)
	}()

	return client
}

func semver(t *testing.T, v string) version.SemVer {
	t.Helper()

	sv, err := version.Parse(v)
	require.NoError(t, err)

	return sv
}

func testCluster(t *testing.T, n int, versions map[int]version.SemVer, expectErr string, nicknames map[int]string) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hash := testutil.RandomBytes32()

	var (
		tcpNodes []host.Host
		servers  []*sync.Server
		clients  []*sync.Client
		keys     []libp2pcrypto.PrivKey
	)

	for i := range n {
		tcpNode, key := newTCPNode(t, int64(i))
		tcpNodes = append(tcpNodes, tcpNode)
		keys = append(keys, key)

		server := sync.NewServer(tcpNode, n-1, hash, versions[i])
		servers = append(servers, server)
	}

	errCh := make(chan error, 1)

	for i := range n {
		for j := range n {
			if i == j {
				continue
			}

			err := tcpNodes[i].Connect(ctx, peer.AddrInfo{
				ID:    tcpNodes[j].ID(),
				Addrs: tcpNodes[j].Addrs(),
			})
			require.NoError(t, err)

			hashSig, err := keys[i].Sign(hash)
			require.NoError(t, err)

			client := sync.NewClient(tcpNodes[i], tcpNodes[j].ID(), hashSig, versions[i], nicknames[i], sync.WithPeriod(time.Millisecond*100))
			clients = append(clients, client)

			ctx := log.WithTopic(ctx, fmt.Sprintf("client%d_%d", i, j))

			go func() {
				err := client.Run(ctx)
				errCh <- err
			}()
		}
	}

	time.Sleep(time.Millisecond) // Wait a bit before starting servers

	for i, server := range servers {
		server.Start(log.WithTopic(ctx, fmt.Sprintf("server%d", i)))
	}

	t.Log("server.AwaitAllConnected")

	for _, server := range servers {
		err := server.AwaitAllConnected(ctx)
		if expectErr != "" {
			require.ErrorContains(t, err, expectErr)
		} else {
			require.NoError(t, err)
		}
	}

	if expectErr != "" {
		return
	}

	for i := range 5 {
		assertAllAtStep(ctx, t, servers, i)

		for _, client := range clients {
			client.SetStep(i + 1)
		}
	}

	t.Log("client.IsConnected")

	for _, client := range clients {
		require.True(t, client.IsConnected())
	}

	t.Log("client.Shutdown")

	for _, client := range clients {
		err := client.Shutdown(ctx)
		require.NoError(t, err)
	}

	err := <-errCh
	if expectErr != "" {
		require.ErrorContains(t, err, expectErr)
		return
	}

	require.NoError(t, err)

	t.Log("server.AwaitAllShutdown")

	for _, server := range servers {
		err := server.AwaitAllShutdown(ctx)
		require.NoError(t, err)
	}
}

func assertAllAtStep(ctx context.Context, t *testing.T, servers []*sync.Server, step int) {
	t.Helper()

	for _, server := range servers {
		err := server.AwaitAllAtStep(ctx, step)
		require.NoError(t, err)

		checkCtx, cancel := context.WithTimeout(ctx, time.Millisecond*10)
		err = server.AwaitAllAtStep(checkCtx, step+1)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		cancel()
	}
}

func newTCPNode(t *testing.T, seed int64) (host.Host, libp2pcrypto.PrivKey) {
	t.Helper()

	key := testutil.GenerateInsecureK1Key(t, int(seed))

	addr := testutil.AvailableAddr(t)
	multiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	priv := (*libp2pcrypto.Secp256k1PrivateKey)(key)

	tcpNode, err := libp2p.New(libp2p.ListenAddrs(multiAddr), libp2p.Identity(priv))
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)

	return tcpNode, priv
}
