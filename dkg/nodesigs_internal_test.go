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

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	"github.com/obolnetwork/charon/testutil"
)

func TestSigsExchange(t *testing.T) {
	n := 32

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

		secrets  []*k1.PrivateKey
		pubkeys  []*k1.PublicKey
		tcpNodes []host.Host
		peers    []peer.ID
		nsigs    []nodeSigBcast
		results  [][][]byte
	)

	defer cancel()

	// Create secretes and libp2p nodes
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)
		pubkeys = append(pubkeys, secret.PubKey())

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
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
		nsigs = append(nsigs, newNodeSigBcast(n, component))
	}

	results = make([][][]byte, n)

	var eg errgroup.Group
	for i := 0; i < n; i++ {
		i := i
		eg.Go(func() error {
			res, err := nsigs[i].exchange(
				ctx,
				bytes.Repeat([]byte{42}, 32),
				secrets[i],
				pubkeys,
				cluster.NodeIdx{PeerIdx: i},
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
		for _, sig := range result {
			require.NotEmpty(t, sig)
		}
	}
}

func TestSigsWrongSig(t *testing.T) {
	n := 32

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

		secrets  []*k1.PrivateKey
		pubkeys  []*k1.PublicKey
		tcpNodes []host.Host
		peers    []peer.ID
		nsigs    []nodeSigBcast
		results  [][][]byte
	)

	defer cancel()

	// Create secretes and libp2p nodes
	for i := 0; i < n; i++ {
		secret, err := k1.GeneratePrivateKey()
		require.NoError(t, err)
		secrets = append(secrets, secret)
		pubkeys = append(pubkeys, secret.PubKey())

		tcpNode := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), secret)
		tcpNodes = append(tcpNodes, tcpNode)

		peers = append(peers, tcpNode.ID())
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
		nsigs = append(nsigs, newNodeSigBcast(n, component))
	}

	results = make([][][]byte, n)

	var eg errgroup.Group
	for i := 0; i < n; i++ {
		i := i

		secret := secrets[i]

		if i+1 == len(secrets) {
			secret = secrets[i-1]
		}

		eg.Go(func() error {
			res, err := nsigs[i].exchange(
				ctx,
				bytes.Repeat([]byte{42}, 32),
				secret,
				pubkeys,
				cluster.NodeIdx{PeerIdx: i},
			)
			if err != nil {
				return err
			}

			results[i] = res

			return nil
		})
	}

	require.ErrorContains(t, eg.Wait(), "signature verification failed on peer lock hash")
}
