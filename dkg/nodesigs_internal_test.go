// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestSigsExchange(t *testing.T) {
	n := 10

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)

		secrets      []*k1.PrivateKey
		tcpNodes     []host.Host
		peers        []peer.ID
		clusterPeers []p2p.Peer
		nsigs        []*nodeSigBcast
		results      [][][]byte
	)

	defer cancel()

	// Create secretes and libp2p nodes
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())

		e, err := enr.New(secret)
		require.NoError(t, err)

		epeer, err := p2p.NewPeerFromENR(e, i)
		require.NoError(t, err)
		clusterPeers = append(clusterPeers, epeer)
	}

	// Connect peers
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	for i := 0; i < n; i++ {
		i := i
		component := bcast.New(tcpNodes[i], peers, secrets[i])
		nsigs = append(nsigs, newNodeSigBcast(
			clusterPeers,
			cluster.NodeIdx{PeerIdx: i},
			component,
		))
	}

	results = make([][][]byte, n)

	var eg errgroup.Group
	for i := 0; i < n; i++ {
		i := i
		eg.Go(func() error {
			res, err := nsigs[i].exchange(
				ctx,
				secrets[i],
				bytes.Repeat([]byte{42}, 32),
			)
			if err != nil {
				return err
			}

			results[i] = res

			return nil
		})
	}

	require.NoError(t, eg.Wait())

	for _, result := range results {
		require.Len(t, result, n)
		for idx, sig := range result {
			require.NotEmpty(t, sig, "index: %v", idx)
		}
	}
}

func TestSigsCallbacks(t *testing.T) {
	n := 10

	var (
		secrets      []*k1.PrivateKey
		tcpNodes     []host.Host
		peers        []peer.ID
		clusterPeers []p2p.Peer
	)

	// Create secretes and libp2p nodes
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())

		e, err := enr.New(secret)
		require.NoError(t, err)

		epeer, err := p2p.NewPeerFromENR(e, i)
		require.NoError(t, err)
		clusterPeers = append(clusterPeers, epeer)
	}

	// Connect peers
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	component := bcast.New(tcpNodes[0], peers, secrets[0])

	ns := newNodeSigBcast(
		clusterPeers,
		cluster.NodeIdx{PeerIdx: 0},
		component,
	)

	t.Run("wrong peer index, equal to ours", func(t *testing.T) {
		msg := &dkgpb.MsgNodeSig{
			Signature: bytes.Repeat([]byte{42}, 32),
			PeerIndex: 0,
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid peer index")
	})

	t.Run("wrong peer index, more than node operators amount", func(t *testing.T) {
		msg := &dkgpb.MsgNodeSig{
			Signature: bytes.Repeat([]byte{42}, 32),
			PeerIndex: uint32(n + 1),
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid peer index")
	})

	t.Run("wrong peer index, peer index is exactly len(peers)", func(t *testing.T) {
		msg := &dkgpb.MsgNodeSig{
			Signature: bytes.Repeat([]byte{42}, 32),
			PeerIndex: uint32(n),
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid peer index")
	})

	t.Run("invalid message type", func(t *testing.T) {
		msg := &dkgpb.FrostMsgKey{
			SourceId: 2, // Invalid SourceID since peers[0].ShareIdx is 1
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid node sig type")
	})

	t.Run("signature verification failed", func(t *testing.T) {
		ns.lockHashData = bytes.Repeat([]byte{42}, 32)

		msg := &dkgpb.MsgNodeSig{
			Signature: bytes.Repeat([]byte{42}, 65), // adding 1 byte for signature header
			PeerIndex: uint32(2),
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid node signature")
	})

	t.Run("malformed signature", func(t *testing.T) {
		msg := &dkgpb.MsgNodeSig{
			Signature: bytes.Repeat([]byte{42}, 2),
			PeerIndex: uint32(2),
		}

		err := ns.broadcastCallback(context.Background(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "verify signature")
	})

	t.Run("ok", func(t *testing.T) {
		lockHash := bytes.Repeat([]byte{42}, 32)
		ns.lockHashData = lockHash

		res, err := k1util.Sign(secrets[2], lockHash)
		require.NoError(t, err)

		msg := &dkgpb.MsgNodeSig{
			Signature: res,
			PeerIndex: uint32(2),
		}

		err = ns.broadcastCallback(context.Background(),
			peers[2],
			"",
			msg,
		)

		require.NoError(t, err)
	})
}
