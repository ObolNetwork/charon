// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p_test

import (
	"context"
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestNewPeer(t *testing.T) {
	p2pKey := testutil.GenerateInsecureK1Key(t, 1)

	record, err := enr.New(p2pKey)
	require.NoError(t, err)

	p, err := p2p.NewPeerFromENR(record, 0)
	require.NoError(t, err)

	require.Equal(t, "16Uiu2HAkzdQ5Y9SYT91K1ue5SxXwgmajXntfScGnLYeip5hHyWmT", p.ID.String())
}

func TestNewHost(t *testing.T) {
	privKey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	_, err = p2p.NewNode(context.Background(), p2p.Config{}, privKey, p2p.NewOpenGater(), false, p2p.NodeTypeTCP)
	require.NoError(t, err)
}

func TestVerifyP2PKey(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	peers, err := lock.Peers()
	require.NoError(t, err)

	for _, key := range keys {
		require.NoError(t, p2p.VerifyP2PKey(peers, key))
	}

	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)
	require.Error(t, p2p.VerifyP2PKey(peers, key))
}

func TestPeerIDKey(t *testing.T) {
	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, keys, _ := cluster.NewForT(t, 1, 3, 4, seed, random)

	peers, err := lock.Peers()
	require.NoError(t, err)

	for i, p := range peers {
		pk, err := p2p.PeerIDToKey(p.ID)
		require.NoError(t, err)
		require.True(t, keys[i].PubKey().IsEqual(pk))

		pID, err := p2p.PeerIDFromKey(pk)
		require.NoError(t, err)
		require.Equal(t, p.ID, pID)
	}
}
