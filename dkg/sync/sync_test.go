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

	clientCtx := log.WithTopic(ctx, "client")
	client := sync.NewClient(clientCtx, clientHost, p2p.Peer{ID: serverHost.ID()}, hashSig, nil)

	require.NoError(t, client.AwaitConnected())
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
