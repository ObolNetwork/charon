// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

type dkgNode struct {
	idx    cluster.NodeIdx
	secret *k1.PrivateKey
	host   host.Host
	board  *pedersen.Board
	config *pedersen.Config
	shares []share
}

type share struct {
	pubKey       tbls.PublicKey
	secretShare  tbls.PrivateKey
	publicShares map[int]tbls.PublicKey
}

func TestRunDKG(t *testing.T) {
	const (
		threshold = 3
		numNodes  = 4
		numVals   = 5
	)

	var (
		peers   []peer.ID
		peerMap = make(map[peer.ID]cluster.NodeIdx)
		session = testutil.RandomArray32()
	)

	nodes := make([]*dkgNode, numNodes)
	for i := 0; i < numNodes; i++ {
		nodes[i] = newDKGNode(t, i)
		peerMap[nodes[i].host.ID()] = nodes[i].idx
		peers = append(peers, nodes[i].host.ID())
	}

	connectNodes(t, nodes)

	for i := range nodes {
		nodes[i].initPedersen(t, threshold, peers, peerMap, session[:])
	}

	// Running DKG
	group, gctx := errgroup.WithContext(t.Context())

	for n := range nodes {
		group.Go(func() error {
			pushFunc := func(valPubKey tbls.PublicKey, secretShare tbls.PrivateKey, publicShares map[int]tbls.PublicKey) {
				nodes[n].shares = append(nodes[n].shares, share{
					pubKey:       valPubKey,
					secretShare:  secretShare,
					publicShares: publicShares,
				})
			}

			return pedersen.RunDKG(gctx, nodes[n].config, nodes[n].board, numVals, pushFunc)
		})
	}

	err := group.Wait()
	require.NoError(t, err, "DKG failed on one or more nodes")

	verifyShares(t, nodes, numVals, threshold)
}

func newDKGNode(t *testing.T, index int) *dkgNode {
	t.Helper()

	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
	t.Cleanup(func() { tcpNode.Close() })

	return &dkgNode{
		idx:    cluster.NodeIdx{PeerIdx: index, ShareIdx: index + 1},
		secret: secret,
		host:   tcpNode,
	}
}

func connectNodes(t *testing.T, nodes []*dkgNode) {
	t.Helper()

	for i := range nodes {
		for j := range nodes {
			nodes[i].host.Peerstore().AddAddrs(nodes[j].host.ID(), nodes[j].host.Addrs(), peerstore.PermanentAddrTTL)
		}
	}
}

func (n *dkgNode) initPedersen(t *testing.T, threshold int, peers []peer.ID, peerMap map[peer.ID]cluster.NodeIdx, session []byte) {
	t.Helper()

	bc := bcast.New(n.host, peers, n.secret)
	logCtx := log.WithCtx(t.Context(), z.Int("index", n.idx.PeerIdx))
	n.config = pedersen.NewConfig(n.host.ID(), peerMap, threshold, session)
	n.board = pedersen.NewBoard(logCtx, n.host, n.config, bc)
}

func verifyShares(t *testing.T, nodes []*dkgNode, numVals, threshold int) {
	t.Helper()

	msg := []byte("data")

	for v := range numVals {
		var (
			sigs    []tbls.Signature
			pshares []tbls.PublicKey
			secrets = make(map[int]tbls.PrivateKey)
		)

		for _, node := range nodes {
			require.Len(t, node.shares, numVals)

			pubKeyShare := node.shares[v].publicShares[node.idx.ShareIdx]
			sig, err := tbls.Sign(node.shares[v].secretShare, msg)
			require.NoError(t, err)

			err = tbls.Verify(pubKeyShare, msg, sig)
			require.NoError(t, err)

			sigs = append(sigs, sig)
			pshares = append(pshares, pubKeyShare)
			secrets[node.idx.ShareIdx] = node.shares[v].secretShare
		}

		aggSig, err := tbls.Aggregate(sigs)
		require.NoError(t, err)

		err = tbls.VerifyAggregate(pshares, aggSig, msg)
		require.NoError(t, err)

		recSecret, err := tbls.RecoverSecret(secrets, uint(len(nodes)), uint(threshold))
		require.NoError(t, err)

		sig, err := tbls.Sign(recSecret, msg)
		require.NoError(t, err)

		err = tbls.Verify(nodes[0].shares[v].pubKey, msg, sig)
		require.NoError(t, err)
	}
}
