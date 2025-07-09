// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus"
	csmocks "github.com/obolnetwork/charon/core/consensus/mocks"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestConsensusController(t *testing.T) {
	var (
		hosts []host.Host
		peers []p2p.Peer
	)

	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, 3, 3, seed, random)

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

	deadlineFunc := func(core.Duty) (time.Time, bool) { return time.Time{}, false }
	debugger := csmocks.NewDebugger(t)
	ctx := context.Background()

	controller, err := consensus.NewConsensusController(ctx, hosts[0], new(p2p.Sender), peers, p2pkeys[0], deadlineFunc, gaterFunc, debugger)
	require.NoError(t, err)
	require.NotNil(t, controller)

	ctx, cancel := context.WithCancel(ctx)
	controller.Start(ctx)

	defer cancel()

	t.Run("default and current consensus", func(t *testing.T) {
		defaultConsensus := controller.DefaultConsensus()
		require.NotNil(t, defaultConsensus)
		require.EqualValues(t, protocols.QBFTv2ProtocolID, defaultConsensus.ProtocolID())
		require.NotEqual(t, defaultConsensus, controller.CurrentConsensus()) // because the current is wrapped
	})

	t.Run("unsupported protocol id", func(t *testing.T) {
		err := controller.SetCurrentConsensusForProtocol(t.Context(), "boo")
		require.ErrorContains(t, err, "unsupported protocol id")
	})
}
