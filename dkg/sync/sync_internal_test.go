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

package sync

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
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestNaiveServerClient(t *testing.T) {
	ctx := context.Background()

	// Start Server
	serverHost := newSyncHost(t, 0)

	// Start Client
	clientHost := newSyncHost(t, 1)
	require.NotEqual(t, clientHost.ID().String(), serverHost.ID().String())

	err := serverHost.Connect(ctx, peer.AddrInfo{
		ID:    clientHost.ID(),
		Addrs: clientHost.Addrs(),
	})
	require.NoError(t, err)

	serverCtx := log.WithTopic(ctx, "server")
	hash := testutil.RandomCoreSignature()
	ch := make(chan *pb.MsgSyncResponse)
	_ = NewServer(serverCtx, serverHost, nil, hash, nil)

	clientCtx := log.WithTopic(ctx, "client")
	_ = NewClient(clientCtx, clientHost, p2p.Peer{ID: serverHost.ID()}, hash, nil, ch)
	actual := <-ch
	require.Equal(t, "", actual.Error)
}

func newSyncHost(t *testing.T, seed int64) host.Host {
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

	return host
}
