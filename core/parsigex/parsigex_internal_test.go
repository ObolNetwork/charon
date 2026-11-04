// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestHandleDropsOversizedSet(t *testing.T) {
	const maxSetSize = 4

	duty := core.Duty{Slot: 1, Type: core.DutyRandao}

	var verifyCalls int

	parSigEx := &ParSigEx{
		verifyFunc: func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error {
			verifyCalls++
			return nil
		},
		gaterFunc:  func(core.Duty) bool { return true },
		maxSetSize: maxSetSize,
	}

	newMsg := func(size int) *pbv1.ParSigExMsg {
		set := make(core.ParSignedDataSet)
		for range size {
			set[testutil.RandomCorePubKey(t)] = core.NewPartialSignedRandao(0, testutil.RandomEth2Signature(), 1)
		}

		setPb, err := core.ParSignedDataSetToProto(set)
		require.NoError(t, err)

		return &pbv1.ParSigExMsg{Duty: core.DutyToProto(duty), DataSet: setPb}
	}

	_, _, err := parSigEx.handle(t.Context(), "", newMsg(maxSetSize+1))
	require.ErrorContains(t, err, "partial signature set too large")
	require.Zero(t, verifyCalls)

	// A set at the limit is still processed.
	_, _, err = parSigEx.handle(t.Context(), "", newMsg(maxSetSize))
	require.NoError(t, err)
	require.Equal(t, maxSetSize, verifyCalls)
}
