// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sync

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/testutil"
)

func TestUpdateStep(t *testing.T) {
	sv, err := version.Parse("v0.1")
	require.NoError(t, err)

	server := &Server{
		defHash:   testutil.RandomBytes32(),
		tcpNode:   nil,
		allCount:  1,
		shutdown:  make(map[peer.ID]struct{}),
		connected: make(map[peer.ID]struct{}),
		steps:     make(map[peer.ID]int),
		version:   sv,
	}

	t.Run("wrong initial step", func(t *testing.T) {
		err = server.updateStep("alpha", 100)
		require.ErrorContains(t, err, "peer reported abnormal initial step, expected 0 or 1")
	})

	t.Run("valid peer step update", func(t *testing.T) {
		err = server.updateStep("bravo", 1)
		require.NoError(t, err)

		err = server.updateStep("bravo", 1)
		require.NoError(t, err) // same step is allowed

		err = server.updateStep("bravo", 2)
		require.NoError(t, err) // next step is allowed
	})

	t.Run("peer step is behind", func(t *testing.T) {
		err = server.updateStep("behind", 1)
		require.NoError(t, err)

		err = server.updateStep("behind", 0)
		require.ErrorContains(t, err, "peer reported step is behind the last known step")
	})

	t.Run("peer step is ahead", func(t *testing.T) {
		err = server.updateStep("ahead", 1)
		require.NoError(t, err)

		err = server.updateStep("ahead", 3)
		require.ErrorContains(t, err, "peer reported step is ahead the last known step")
	})
}
