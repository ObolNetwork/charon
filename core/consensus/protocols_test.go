// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus_test

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/consensus"
)

func TestIsSupportedProtocolName(t *testing.T) {
	require.True(t, consensus.IsSupportedProtocolName("qbft"))
	require.False(t, consensus.IsSupportedProtocolName("unreal"))
}

func TestProtocols(t *testing.T) {
	require.Equal(t, []protocol.ID{
		consensus.QBFTv2ProtocolID,
	}, consensus.Protocols())
}
