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

package sync_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/testutil"
)

func TestSyncProtocol(t *testing.T) {
	t.Run("2", func(t *testing.T) {
		testCluster(t, 2)
	})

	t.Run("3", func(t *testing.T) {
		testCluster(t, 3)
	})

	t.Run("5", func(t *testing.T) {
		testCluster(t, 5)
	})
}

func testCluster(t *testing.T, n int) {
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

		server := sync.NewServer(tcpNode, n-1, hash)
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

			client := sync.NewClient(tcpNodes[i], tcpNodes[j].ID(), hashSig)
			clients = append(clients, client)

			ctx := log.WithTopic(ctx, fmt.Sprintf("client%d_%d", i, j))
			go func() {
				err := client.Run(ctx)
				require.NoError(t, err)
			}()
		}
	}

	time.Sleep(time.Millisecond) // Wait a bit before starting servers

	for i, server := range servers {
		server.Start(log.WithTopic(ctx, fmt.Sprintf("server%d", i)))
	}

	t.Log("client.IsConnected")
	for _, client := range clients {
		err := client.IsConnected(ctx)
		require.NoError(t, err)
	}

	t.Log("server.AwaitAllConnected")
	for _, server := range servers {
		err := server.AwaitAllConnected(ctx)
		require.NoError(t, err)
	}

	go func() {
		t.Log("client.Shutdown")
		for _, client := range clients {
			err := client.Shutdown(ctx)
			require.NoError(t, err)
		}
	}()

	t.Log("server.AwaitAllShutdown")
	for _, server := range servers {
		err := server.AwaitAllShutdown(ctx)
		require.NoError(t, err)
	}
}

func newTCPNode(t *testing.T, seed int64) (host.Host, libp2pcrypto.PrivKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(seed)))
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t)
	multiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	require.NoError(t, err)

	tcpNode, err := libp2p.New(libp2p.ListenAddrs(multiAddr), libp2p.Identity(priv))
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)

	return tcpNode, priv
}
