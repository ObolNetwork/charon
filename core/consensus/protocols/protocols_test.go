// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package protocols_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/consensus/protocols"
)

func TestIsSupportedProtocolName(t *testing.T) {
	require.True(t, protocols.IsSupportedProtocolName("qbft"))
	require.False(t, protocols.IsSupportedProtocolName("unreal"))
}

func TestProtocols(t *testing.T) {
	require.Equal(t, []protocol.ID{
		protocols.QBFTv2ProtocolID,
	}, protocols.Protocols())
}

func TestMostPreferredConsensusProtocol(t *testing.T) {
	t.Run("default is qbft", func(t *testing.T) {
		require.Equal(t, protocols.QBFTv2ProtocolID, protocols.MostPreferredConsensusProtocol([]string{"unreal"}))
		require.Equal(t, protocols.QBFTv2ProtocolID, protocols.MostPreferredConsensusProtocol([]string{}))
	})

	t.Run("latest abft is preferred", func(t *testing.T) {
		pp := []string{
			"/charon/consensus/abft/3.0.0",
			"/charon/consensus/abft/1.0.0",
			"/charon/consensus/qbft/1.0.0",
		}
		require.Equal(t, "/charon/consensus/abft/3.0.0", protocols.MostPreferredConsensusProtocol(pp))
	})
}

func TestBumpProtocolsByName(t *testing.T) {
	intitial := []protocol.ID{
		"/charon/consensus/hotstuff/1.0.0",
		"/charon/consensus/abft/3.0.0",
		"/charon/consensus/abft/1.0.0",
		"/charon/consensus/qbft/1.0.0",
	}

	bumped := protocols.BumpProtocolsByName("abft", intitial)
	require.Equal(t, []protocol.ID{
		"/charon/consensus/abft/3.0.0",
		"/charon/consensus/abft/1.0.0",
		"/charon/consensus/hotstuff/1.0.0",
		"/charon/consensus/qbft/1.0.0",
	}, bumped)
}
