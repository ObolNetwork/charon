// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/drand/kyber"
	kbls "github.com/drand/kyber-bls12381"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/testutil"
)

type testNode struct {
	idx    cluster.NodeIdx
	secret *k1.PrivateKey
	host   host.Host
	board  *pedersen.Board
	config *pedersen.Config
	shares []share
}

func newTestNode(t *testing.T, index int) *testNode {
	t.Helper()

	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
	t.Cleanup(func() { tcpNode.Close() })

	return &testNode{
		idx:    cluster.NodeIdx{PeerIdx: index, ShareIdx: index + 1},
		secret: secret,
		host:   tcpNode,
	}
}

func connectTestNodes(t *testing.T, nodes []*testNode) {
	t.Helper()

	for i := range nodes {
		for j := range nodes {
			nodes[i].host.Peerstore().AddAddrs(nodes[j].host.ID(), nodes[j].host.Addrs(), peerstore.PermanentAddrTTL)
		}
	}
}

func (n *testNode) initBoard(t *testing.T, threshold int, peers []peer.ID, peerMap map[peer.ID]cluster.NodeIdx, session []byte) {
	t.Helper()

	bc := bcast.New(n.host, peers, n.secret)
	logCtx := log.WithCtx(t.Context(), z.Int("index", n.idx.PeerIdx))
	n.config = pedersen.NewConfig(n.host.ID(), peerMap, threshold, session)
	n.board = pedersen.NewBoard(logCtx, n.host, n.config, bc)
}

func testSuite(t *testing.T) kdkg.Suite {
	t.Helper()

	return kbls.NewBLS12381Suite().G1().(kdkg.Suite)
}

func randomScalar(t *testing.T) kyber.Scalar {
	t.Helper()

	return testSuite(t).Scalar().Pick(random.New())
}

func randomScalarBytes(t *testing.T) []byte {
	t.Helper()

	scalar := randomScalar(t)
	b, err := scalar.MarshalBinary()
	require.NoError(t, err)

	return b
}

func randomPoint(t *testing.T) kyber.Point {
	t.Helper()

	private := randomScalar(t)
	public := testSuite(t).Point().Mul(private, nil)

	return public
}
