// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	versions := make(map[int]string)
	for i := 0; i < 5; i++ {
		versions[i] = version.Version
	}

	t.Run("2", func(t *testing.T) {
		testCluster(t, 2, versions, false)
	})

	t.Run("3", func(t *testing.T) {
		testCluster(t, 3, versions, false)
	})

	t.Run("5", func(t *testing.T) {
		testCluster(t, 5, versions, false)
	})
}

func TestInvalidVersion(t *testing.T) {
	testCluster(t, 2, map[int]string{
		0: "1.0",
		1: "2.0",
	}, true)
}

func testCluster(t *testing.T, n int, versions map[int]string, expectErr bool) {
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
	for i := 0; i < n; i++ {
		tcpNode, key := newTCPNode(t, int64(i))
		tcpNodes = append(tcpNodes, tcpNode)
		keys = append(keys, key)

		server := sync.NewServer(tcpNode, n-1, hash, versions[i])
		servers = append(servers, server)
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
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

			client := sync.NewClient(tcpNodes[i], tcpNodes[j].ID(), hashSig, versions[i])
			clients = append(clients, client)

			ctx := log.WithTopic(ctx, fmt.Sprintf("client%d_%d", i, j))
			go func() {
				err := client.Run(ctx)
				if expectErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
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
		if expectErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}

	if expectErr {
		return
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

	t.Log("server.AwaitAllShutdown")
	for _, server := range servers {
		err := server.AwaitAllShutdown(ctx)
		require.NoError(t, err)
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
