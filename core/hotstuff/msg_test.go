// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/core"
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

func TestMsgToProto(t *testing.T) {
	msg := &hotstuff.Msg{
		Duty:      core.NewProposerDuty(1),
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

	protoMsg := msg.ToProto()
	pbytes, err := proto.Marshal(protoMsg)
	require.NoError(t, err)

	err = proto.Unmarshal(pbytes, protoMsg)
	require.NoError(t, err)

	msg2 := hotstuff.ProtoToMsg(protoMsg)
	require.EqualValues(t, msg, msg2)
}
