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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestAwaitAllConnected -race

func TestAwaitConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Server
	serverHost, _ := newSyncHost(t, 0)

	// Start Client
	clientHost, key := newSyncHost(t, 1)
	require.NotEqual(t, clientHost.ID().String(), serverHost.ID().String())

	err := serverHost.Connect(ctx, peer.AddrInfo{
		ID:    clientHost.ID(),
		Addrs: clientHost.Addrs(),
	})
	require.NoError(t, err)

	hash := testutil.RandomBytes32()
	hashSig, err := key.Sign(hash)
	require.NoError(t, err)

	serverCtx := log.WithTopic(ctx, "server")
	_ = sync.NewServer(serverCtx, serverHost, []p2p.Peer{{ID: clientHost.ID()}}, hash, nil)

	clientCtx := log.WithTopic(context.Background(), "client")
	client := sync.NewClient(clientCtx, clientHost, p2p.Peer{ID: serverHost.ID()}, hashSig, nil)

	require.NoError(t, client.AwaitConnected())
}

func TestAwaitAllConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numClients = 3
	seed := 0
	serverHost, _ := newSyncHost(t, int64(seed))
	var (
		peers       []p2p.Peer
		keys        []libp2pcrypto.PrivKey
		clientHosts []host.Host
	)
	for i := 0; i < numClients; i++ {
		seed++
		clientHost, key := newSyncHost(t, int64(seed))
		require.NotEqual(t, clientHost.ID().String(), serverHost.ID().String())

		err := serverHost.Connect(ctx, peer.AddrInfo{
			ID:    clientHost.ID(),
			Addrs: clientHost.Addrs(),
		})
		require.NoError(t, err)

		clientHosts = append(clientHosts, clientHost)
		keys = append(keys, key)
		peers = append(peers, p2p.Peer{ID: clientHost.ID()})
	}

	hash := testutil.RandomBytes32()
	server := sync.NewServer(log.WithTopic(ctx, "server"), serverHost, peers, hash, nil)

	var clients []sync.Client
	for i := 0; i < numClients; i++ {
		hashSig, err := keys[i].Sign(hash)
		require.NoError(t, err)

		client := sync.NewClient(log.WithTopic(context.Background(), "client"), clientHosts[i], p2p.Peer{ID: serverHost.ID()}, hashSig, nil)
		clients = append(clients, client)
	}

	for i := 0; i < numClients; i++ {
		require.NoError(t, clients[i].AwaitConnected())
	}

	require.NoError(t, server.AwaitAllConnected())
}

func newSyncHost(t *testing.T, seed int64) (host.Host, libp2pcrypto.PrivKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(seed)))
	require.NoError(t, err)

	priv, err := libp2pcrypto.UnmarshalSecp256k1PrivateKey(crypto.FromECDSA(key))
	require.NoError(t, err)

	addr := testutil.AvailableAddr(t)
	multiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	host, err := libp2p.New(libp2p.ListenAddrs(multiAddr), libp2p.Identity(priv))
	require.NoError(t, err)

	return host, priv
}
