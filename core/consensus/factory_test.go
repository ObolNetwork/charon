// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestNewConsensusFactory(t *testing.T) {
	var hosts []host.Host
	var peers []p2p.Peer

	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, 3, 3, seed, random)

	snifferFunc := func(msgs *pbv1.SniffedConsensusInstance) {}
	gaterFunc := func(core.Duty) bool { return true }

	for i := range 3 {
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

		peers = append(peers, p)
		hosts = append(hosts, h)
	}

	factory := consensus.NewConsensusFactory(hosts[0], new(p2p.Sender), peers, p2pkeys[0], testDeadliner{}, gaterFunc, snifferFunc)
	require.NotNil(t, factory)

	cons, err := factory.New(consensus.QBFTv2ProtocolID)
	require.NoError(t, err)
	require.NotNil(t, cons)

	t.Run("unknown protocol", func(t *testing.T) {
		_, err := factory.New("unknown")
		require.Error(t, err)
	})
}
