// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package app

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

func TestQBFTDebugger(t *testing.T) {
	var (
		instances []*pbv1.SniffedConsensusInstance
		debug     = new(qbftDebugger)
	)

	for i := 0; i < 10; i++ {
		instance := &pbv1.SniffedConsensusInstance{
			Msgs: []*pbv1.SniffedConsensusMsg{
				{
					Timestamp: timestamppb.Now(),
					Msg: &pbv1.ConsensusMsg{
						Msg:           randomQBFTMessage(),
						Justification: []*pbv1.QBFTMsg{randomQBFTMessage(), randomQBFTMessage()},
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

func randomQBFTMessage() *pbv1.QBFTMsg {
	return &pbv1.QBFTMsg{
		Type:          rand.Int63(),
		Duty:          &pbv1.Duty{Slot: rand.Int63()},
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		PreparedRound: rand.Int63(),
	}
}
