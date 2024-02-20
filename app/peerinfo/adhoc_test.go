// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo_test

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/peerinfo"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestDoOnce(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)

	vers := version.Version
	lockHash := []byte("123")
	gitHash := "abc"
	// Register the server handler that either
	_ = peerinfo.New(server, []peer.ID{server.ID(), client.ID()}, vers, lockHash, gitHash, p2p.SendReceive, true)

	info, _, ok, err := peerinfo.DoOnce(context.Background(), client, server.ID())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, vers.String(), info.CharonVersion)
	require.Equal(t, gitHash, info.GitHash)
	require.Equal(t, lockHash, info.LockHash)
	require.True(t, info.BuilderApiEnabled)
}
