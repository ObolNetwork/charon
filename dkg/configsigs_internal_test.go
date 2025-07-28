// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestConfigSigsExchange(t *testing.T) {
	n := 7

	var (
		ctx, cancel = context.WithTimeout(t.Context(), 45*time.Second)

		secrets      []*k1.PrivateKey
		tcpNodes     []host.Host
		peers        []peer.ID
		clusterPeers []p2p.Peer
		csigs        []*configSigBcast
		results      [][]configSigTuple
	)

	defer cancel()

	// Create secretes and libp2p nodes
	for i := range n {
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
	for i := range n {
		for j := range n {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	for i := range n {
		component := bcast.New(tcpNodes[i], peers, secrets[i])
		csigs = append(csigs, newConfigSigBcast(
			clusterPeers,
			cluster.NodeIdx{PeerIdx: i},
			component,
		))
	}

	results = make([][]configSigTuple, n)

	var eg errgroup.Group
	for i := range n {
		eg.Go(func() error {
			ccs := byte(i*10 + 1)
			ocs := byte(i*10 + 2)
			oes := byte(i*10 + 3)

			res, err := csigs[i].exchange(
				ctx,
				bytes.Repeat([]byte{ccs}, 65), // creatorConfigSig
				bytes.Repeat([]byte{ocs}, 65), // operatorConfigSig
				bytes.Repeat([]byte{oes}, 65), // operatorEnrSig
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

		for idx, tup := range result {
			require.NotEmpty(t, tup)

			require.Len(t, tup.creatorConfigSig, 65)
			require.Len(t, tup.operatorConfigSig, 65)
			require.Len(t, tup.operatorEnrSig, 65)

			ccs := byte(idx*10 + 1)
			ocs := byte(idx*10 + 2)
			oes := byte(idx*10 + 3)
			require.Equal(t, bytes.Repeat([]byte{ccs}, 65), tup.creatorConfigSig)
			require.Equal(t, bytes.Repeat([]byte{ocs}, 65), tup.operatorConfigSig)
			require.Equal(t, bytes.Repeat([]byte{oes}, 65), tup.operatorEnrSig)
		}
	}
}

func TestConfigSigsCallbacks(t *testing.T) {
	n := 10

	var (
		secrets      []*k1.PrivateKey
		tcpNodes     []host.Host
		peers        []peer.ID
		clusterPeers []p2p.Peer
	)

	// Create secretes and libp2p nodes
	for i := range n {
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
	for i := range n {
		for j := range n {
			tcpNodes[i].Peerstore().AddAddrs(tcpNodes[j].ID(), tcpNodes[j].Addrs(), peerstore.PermanentAddrTTL)
		}
	}

	component := bcast.New(tcpNodes[0], peers, secrets[0])

	cs := newConfigSigBcast(
		clusterPeers,
		cluster.NodeIdx{PeerIdx: 0},
		component,
	)

	t.Run("wrong peer index, equal to ours", func(t *testing.T) {
		msg := &dkgpb.MsgConfigSig{
			CreatorConfigSig:  bytes.Repeat([]byte{1}, 32),
			OperatorConfigSig: bytes.Repeat([]byte{2}, 32),
			OperatorEnrSig:    bytes.Repeat([]byte{3}, 32),
			PeerIndex:         0,
		}

		err := cs.broadcastCallback(t.Context(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid peer index")
	})

	t.Run("wrong peer index, more than node operators amount", func(t *testing.T) {
		msg := &dkgpb.MsgConfigSig{
			CreatorConfigSig:  bytes.Repeat([]byte{1}, 32),
			OperatorConfigSig: bytes.Repeat([]byte{2}, 32),
			OperatorEnrSig:    bytes.Repeat([]byte{3}, 32),
			PeerIndex:         uint32(n + 1),
		}

		err := cs.broadcastCallback(t.Context(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid peer index")
	})

	t.Run("wrong peer index, peer index is exactly len(peers)", func(t *testing.T) {
		msg := &dkgpb.MsgConfigSig{
			CreatorConfigSig:  bytes.Repeat([]byte{1}, 32),
			OperatorConfigSig: bytes.Repeat([]byte{2}, 32),
			OperatorEnrSig:    bytes.Repeat([]byte{3}, 32),
			PeerIndex:         uint32(n),
		}

		err := cs.broadcastCallback(t.Context(),
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

		err := cs.broadcastCallback(t.Context(),
			peers[0],
			"",
			msg,
		)

		require.ErrorContains(t, err, "invalid config sig type")
	})

	t.Run("ok", func(t *testing.T) {
		msg := &dkgpb.MsgConfigSig{
			CreatorConfigSig:  bytes.Repeat([]byte{1}, 32),
			OperatorConfigSig: bytes.Repeat([]byte{2}, 32),
			OperatorEnrSig:    bytes.Repeat([]byte{3}, 32),
			PeerIndex:         uint32(2),
		}

		err := cs.broadcastCallback(t.Context(),
			peers[2],
			"",
			msg,
		)

		require.NoError(t, err)
	})
}
