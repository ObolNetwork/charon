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
		Type:   hotstuff.MsgPrepare,
		View:   1,
		Sender: 1,
	}

	msg2 := &hotstuff.Msg{
		Type:   hotstuff.MsgCommit,
		View:   1,
		Sender: 2,
	}

	c.AddMsg(msg1)
	c.AddMsg(msg1) // deduplication
	c.AddMsg(msg2)
	c.AddMsg(msg2) // deduplication

	mm := c.MatchingMsg(hotstuff.MsgPrepare, 1)
	require.Len(t, mm, 1)
	require.Equal(t, msg1, mm[0])

	mm = c.MatchingMsg(hotstuff.MsgCommit, 1)
	require.Len(t, mm, 1)
	require.Equal(t, msg2, mm[0])

	mm = c.MatchingMsg(hotstuff.MsgDecide, 2)
	require.Empty(t, mm)

	msg3 := &hotstuff.Msg{
		Type:   hotstuff.MsgPrepare,
		View:   1,
		Sender: 2,
	}

	c.AddMsg(msg3)
	mm = c.MatchingMsg(hotstuff.MsgPrepare, 1)
	require.Len(t, mm, 2)
	require.Equal(t, msg1, mm[0])
	require.Equal(t, msg3, mm[1])
}