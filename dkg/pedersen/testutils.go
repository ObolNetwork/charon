// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"encoding/hex"
	"testing"
	"time"

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
	"github.com/obolnetwork/charon/dkg/share"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

type TestNode struct {
	NodeIdx    cluster.NodeIdx
	NodeSecret *k1.PrivateKey
	NodeHost   host.Host
	Board      *Board
	Config     *Config
	Shares     []share.Share
}

func NewTestNode(t *testing.T, index int) *TestNode {
	t.Helper()

	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	return NewTestNodeWithKey(t, index, secret)
}

func NewTestNodeWithKey(t *testing.T, index int, key *k1.PrivateKey) *TestNode {
	t.Helper()

	tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), key)
	t.Cleanup(func() { tcpNode.Close() })

	return &TestNode{
		NodeIdx:    cluster.NodeIdx{PeerIdx: index, ShareIdx: index + 1},
		NodeSecret: key,
		NodeHost:   tcpNode,
	}
}

func ConnectTestNodes(t *testing.T, nodes []*TestNode) {
	t.Helper()

	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			nodes[i].NodeHost.Peerstore().AddAddrs(nodes[j].NodeHost.ID(), nodes[j].NodeHost.Addrs(), peerstore.PermanentAddrTTL)
		}
	}
}

func (n *TestNode) InitBoard(t *testing.T, threshold int, peers []peer.ID, peerMap map[peer.ID]cluster.NodeIdx, session []byte) {
	t.Helper()

	bc := bcast.New(n.NodeHost, peers, n.NodeSecret)
	logCtx := log.WithCtx(t.Context(), z.Int("index", n.NodeIdx.PeerIdx))
	n.Config = NewConfig(n.NodeHost.ID(), peerMap, threshold, session, 3*time.Second, nil)
	n.Board = NewBoard(logCtx, n.NodeHost, n.Config, bc)
}

func TestSuite(t *testing.T) kdkg.Suite {
	t.Helper()

	s, ok := kbls.NewBLS12381Suite().G1().(kdkg.Suite)
	require.True(t, ok)

	return s
}

func RandomScalar(t *testing.T) kyber.Scalar {
	t.Helper()

	return TestSuite(t).Scalar().Pick(random.New())
}

func RandomScalarBytes(t *testing.T) []byte {
	t.Helper()

	scalar := RandomScalar(t)
	b, err := scalar.MarshalBinary()
	require.NoError(t, err)

	return b
}

func RandomPoint(t *testing.T) kyber.Point {
	t.Helper()

	private := RandomScalar(t)
	public := TestSuite(t).Point().Mul(private, nil)

	return public
}

func MustDecodeHex(t *testing.T, str string) []byte {
	t.Helper()

	b, err := hex.DecodeString(str)
	require.NoError(t, err)

	return b
}

func VerifyShares(t *testing.T, nodes []*TestNode, numVals, threshold int) {
	t.Helper()

	msg := []byte("data")

	for v := range numVals {
		var (
			sigs    []tbls.Signature
			pshares []tbls.PublicKey
			secrets = make(map[int]tbls.PrivateKey)
		)

		for _, node := range nodes {
			require.Len(t, node.Shares, numVals)

			pubKeyShare := node.Shares[v].PublicShares[node.NodeIdx.ShareIdx]
			sig, err := tbls.Sign(node.Shares[v].SecretShare, msg)
			require.NoError(t, err)

			err = tbls.Verify(pubKeyShare, msg, sig)
			require.NoError(t, err)

			sigs = append(sigs, sig)
			pshares = append(pshares, pubKeyShare)
			secrets[node.NodeIdx.ShareIdx] = node.Shares[v].SecretShare
		}

		aggSig, err := tbls.Aggregate(sigs)
		require.NoError(t, err)

		err = tbls.VerifyAggregate(pshares, aggSig, msg)
		require.NoError(t, err)

		recSecret, err := tbls.RecoverSecret(secrets, uint(len(nodes)), uint(threshold))
		require.NoError(t, err)

		sig, err := tbls.Sign(recSecret, msg)
		require.NoError(t, err)

		err = tbls.Verify(nodes[0].Shares[v].PubKey, msg, sig)
		require.NoError(t, err)
	}
}

func VerifyDiff(t *testing.T, nodes []*TestNode, oldShares [][]share.Share, numVals int) {
	t.Helper()

	for n := range nodes {
		dkgNodeShares := oldShares[n]
		reshareNodeShares := nodes[n].Shares

		for v := range numVals {
			// Validator public keys should be the same after resharing
			require.Equal(t, dkgNodeShares[v].PubKey, reshareNodeShares[v].PubKey)

			// The secret shares should be different, because of resharing
			require.NotEqual(t, dkgNodeShares[v].SecretShare, reshareNodeShares[v].SecretShare)
		}
	}
}
