// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestCollector(t *testing.T) {
	c := hotstuff.NewCollector()

	msg1 := &hotstuff.Msg{
		Type: hotstuff.MsgPrepare,
		View: 1,
	}

	msg2 := &hotstuff.Msg{
		Type: hotstuff.MsgCommit,
		View: 1,
	}

	c.AddMsg(msg1, 1)
	c.AddMsg(msg1, 1) // deduplication
	c.AddMsg(msg2, 2)
	c.AddMsg(msg2, 2) // deduplication

	mm, ids := c.MatchingMsg(hotstuff.MsgPrepare, 1)
	require.Len(t, mm, 1)
	require.Len(t, ids, 1)
	require.Equal(t, msg1, mm[0])
	require.EqualValues(t, 1, ids[0])

	mm, ids = c.MatchingMsg(hotstuff.MsgCommit, 1)
	require.Len(t, mm, 1)
	require.Len(t, ids, 1)
	require.Equal(t, msg2, mm[0])
	require.EqualValues(t, 2, ids[0])

	mm, ids = c.MatchingMsg(hotstuff.MsgDecide, 2)
	require.Empty(t, mm)
	require.Empty(t, ids)

	msg3 := &hotstuff.Msg{
		Type: hotstuff.MsgPrepare,
		View: 1,
	}

	c.AddMsg(msg3, 2)
	mm, ids = c.MatchingMsg(hotstuff.MsgPrepare, 1)
	require.Len(t, mm, 2)
	require.Len(t, ids, 2)
	require.Equal(t, msg1, mm[0])
	require.Equal(t, msg3, mm[1])
	require.EqualValues(t, 1, ids[0])
	require.EqualValues(t, 2, ids[1])
}
