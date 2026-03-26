// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package priority

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

func TestHashProto(t *testing.T) {
	tests := []struct {
		name     string
		msg      proto.Message
		expected string
	}{
		{
			name:     "empty_priority_msg",
			msg:      &pbv1.PriorityMsg{},
			expected: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "priority_msg_peer1",
			msg:      &pbv1.PriorityMsg{PeerId: "peer1"},
			expected: "0x1a05706565723100000000000000000000000000000000000000000000000000",
		},
		{
			name:     "priority_msg_peer2",
			msg:      &pbv1.PriorityMsg{PeerId: "peer2"},
			expected: "0x1a05706565723200000000000000000000000000000000000000000000000000",
		},
		{
			name: "priority_msg_with_signature",
			msg: &pbv1.PriorityMsg{
				PeerId:    "peer1",
				Signature: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			expected: "0x1a0570656572312204deadbeef00000000000000000000000000000000000000",
		},
		{
			name:     "empty_priority_result",
			msg:      &pbv1.PriorityResult{},
			expected: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "priority_result_with_msgs",
			msg: &pbv1.PriorityResult{
				Msgs: []*pbv1.PriorityMsg{{PeerId: "peer1"}},
			},
			expected: "0x0a071a0570656572310000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hashProto(tt.msg)
			require.NoError(t, err)
			require.Equal(t, tt.expected, "0x"+hex.EncodeToString(got[:]))
		})
	}
}
