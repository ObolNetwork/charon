// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	charonCluster "github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	hs "github.com/obolnetwork/charon/core/hotstuff"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestTransport(t *testing.T) {
	const nodes = 3

	var (
		peers     []p2p.Peer
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := charonCluster.NewForT(t, 1, nodes, nodes, 0, random)

	for i := range nodes {
		addr := testutil.AvailableAddr(t)
		mAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
		require.NoError(t, err)

		priv := (*libp2pcrypto.Secp256k1PrivateKey)(p2pkeys[i])
		h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrs(mAddr))
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)

		record, err := enr.Parse(lock.Operators[i].ENR)
		require.NoError(t, err)

		p, err := p2p.NewPeerFromENR(record, i)
		require.NoError(t, err)

		hostsInfo = append(hostsInfo, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
		peers = append(peers, p)
		hosts = append(hosts, h)
	}

	transports := make([]*transport, nodes)

	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			hosts[i].Peerstore().AddAddrs(hostsInfo[j].ID, hostsInfo[j].Addrs, peerstore.PermanentAddrTTL)
		}

		transports[i] = newTransport(hosts[i], new(p2p.Sender), peers)

		p2p.RegisterHandler("hotstuff", hosts[i],
			protocols.HotStuffv1ProtocolID,
			func() proto.Message { return new(pbv1.HotStuffMsg) },
			transports[i].P2PHandler)
	}

	ctx := context.Background()
	tmsg := &hs.Msg{
		Type:  hs.MsgCommit,
		View:  2,
		Value: []byte("hello"),
		QC: &hs.QC{
			Type: hs.MsgPreCommit,
			View: 1,
		},
	}

	t.Run("bcast", func(t *testing.T) {
		err := transports[0].Broadcast(ctx, tmsg)
		require.NoError(t, err)

		for i := range nodes {
			rmsg := <-transports[i].ReceiveCh()
			require.EqualValues(t, tmsg, rmsg)
		}
	})

	t.Run("to self", func(t *testing.T) {
		err := transports[0].SendTo(ctx, 1, tmsg)
		require.NoError(t, err)

		rmsg := <-transports[0].ReceiveCh()
		require.EqualValues(t, tmsg, rmsg)
	})

	t.Run("to peer", func(t *testing.T) {
		err := transports[0].SendTo(ctx, 2, tmsg)
		require.NoError(t, err)

		rmsg := <-transports[1].ReceiveCh()
		require.EqualValues(t, tmsg, rmsg)
	})
}
