// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"compress/gzip"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

func TestDebugger(t *testing.T) {
	var (
		instances []*pbv1.SniffedConsensusInstance
		debug     = new(debugger)
	)

	for range 10 {
		instance := &pbv1.SniffedConsensusInstance{
			Msgs: []*pbv1.SniffedConsensusMsg{
				{
					Timestamp: timestamppb.Now(),
					// Eventually the ConsensusMsg will be replaced by a more generic message type.
					Msg: &pbv1.QBFTConsensusMsg{
						Msg:           randomQBFTMsg(),
						Justification: []*pbv1.QBFTMsg{randomQBFTMsg(), randomQBFTMsg()},
					},
				},
			},
		}
		instances = append(instances, instance)
		debug.AddInstance(instance)
	}

	srv := httptest.NewServer(debug)

	res, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	r, err := gzip.NewReader(res.Body)
	require.NoError(t, err)

	b, err := io.ReadAll(r)
	require.NoError(t, err)

	resp := new(pbv1.SniffedConsensusInstances)
	err = proto.Unmarshal(b, resp)
	require.NoError(t, err)

	require.True(t, proto.Equal(&pbv1.SniffedConsensusInstances{Instances: instances}, resp))
}

func randomQBFTMsg() *pbv1.QBFTMsg {
	return &pbv1.QBFTMsg{
		Type:          rand.Int63(),
		Duty:          &pbv1.Duty{Slot: rand.Uint64()},
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		PreparedRound: rand.Int63(),
	}
}
