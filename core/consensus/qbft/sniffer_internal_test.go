// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"testing"

	"github.com/stretchr/testify/require"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

func TestSniffer(t *testing.T) {
	sniffer := newSniffer(3, 1)

	sniffer.Add(&pbv1.QBFTConsensusMsg{
		Msg: newRandomQBFTMsg(t),
	})
	sniffer.Add(&pbv1.QBFTConsensusMsg{
		Msg: newRandomQBFTMsg(t),
	})

	instance := sniffer.Instance()

	require.EqualValues(t, 3, instance.GetNodes())
	require.EqualValues(t, 1, instance.GetPeerIdx())
	require.NotNil(t, instance.GetStartedAt())
	require.Len(t, instance.GetMsgs(), 2)
}
