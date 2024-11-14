// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/hotstuff"
)

func TestMsgTypeString(t *testing.T) {
	tests := []struct {
		t    hotstuff.MsgType
		tstr string
	}{
		{hotstuff.MsgNewView, "new_view"},
		{hotstuff.MsgPrepare, "prepare"},
		{hotstuff.MsgPreCommit, "pre_commit"},
		{hotstuff.MsgCommit, "commit"},
		{hotstuff.MsgDecide, "decide"},
	}

	for _, tt := range tests {
		t.Run(tt.tstr, func(t *testing.T) {
			require.Equal(t, tt.tstr, tt.t.String())
		})
	}
}

func TestNextMsgType(t *testing.T) {
	tests := []struct {
		t    hotstuff.MsgType
		next hotstuff.MsgType
	}{
		{hotstuff.MsgNewView, hotstuff.MsgPrepare},
		{hotstuff.MsgPrepare, hotstuff.MsgPreCommit},
		{hotstuff.MsgPreCommit, hotstuff.MsgCommit},
		{hotstuff.MsgCommit, hotstuff.MsgDecide},
		{hotstuff.MsgDecide, hotstuff.MsgNewView},
	}

	for _, tt := range tests {
		t.Run(tt.t.String(), func(t *testing.T) {
			require.Equal(t, tt.next, tt.t.NextMsgType())
		})
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		p    hotstuff.Phase
		pstr string
	}{
		{hotstuff.PreparePhase, "prepare"},
		{hotstuff.PreCommitPhase, "pre_commit"},
		{hotstuff.CommitPhase, "commit"},
		{hotstuff.DecidePhase, "decide"},
		{hotstuff.TerminalPhase, "terminal"},
	}

	for _, tt := range tests {
		t.Run(tt.pstr, func(t *testing.T) {
			require.Equal(t, tt.pstr, tt.p.String())
		})
	}
}

func TestNextPhase(t *testing.T) {
	tests := []struct {
		p    hotstuff.Phase
		next hotstuff.Phase
	}{
		{hotstuff.PreparePhase, hotstuff.PreCommitPhase},
		{hotstuff.PreCommitPhase, hotstuff.CommitPhase},
		{hotstuff.CommitPhase, hotstuff.DecidePhase},
		{hotstuff.DecidePhase, hotstuff.TerminalPhase},
		{hotstuff.TerminalPhase, hotstuff.TerminalPhase},
	}

	for _, tt := range tests {
		t.Run(tt.p.String(), func(t *testing.T) {
			require.Equal(t, tt.next, tt.p.NextPhase())
		})
	}
}

func TestIDToIndex(t *testing.T) {
	require.Equal(t, 0, hotstuff.ID(1).ToIndex())
	require.Equal(t, 1, hotstuff.ID(2).ToIndex())
}

func TestMsgToProto(t *testing.T) {
	msg := &hotstuff.Msg{
		Type:      hotstuff.MsgPrepare,
		View:      3,
		Vote:      true,
		Value:     []byte("hello"),
		ValueHash: [32]byte{1},
		Signature: []byte("sig"),
		QC: &hotstuff.QC{
			Type:      hotstuff.MsgCommit,
			View:      2,
			ValueHash: [32]byte{2},
			Signatures: [][]byte{
				[]byte("sig1"),
				[]byte("sig2"),
			},
		},
	}

	msg2 := hotstuff.ProtoToMsg(msg.ToProto())
	require.EqualValues(t, msg, msg2)
}
