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

package consensus

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

var sniffedFile = flag.String("sniffed-file", "/Users/xenowits/Downloads/qbft_messages.pb.gz", "path to sniffed file")

// TestSniffedInstances simulates all the instances in the sniffed file.
func TestSniffedFile(t *testing.T) {
	if *sniffedFile == "" {
		t.Skip("no sniffed file provided")
	}

	ctx := context.Background()

	instances := parseSniffedFile(t, *sniffedFile)

	log.Info(ctx, "Parsed sniffed file",
		z.Int("instances", len(instances.Instances)),
		z.Str("git_hash", instances.GitHash),
	)

	for i, instance := range instances.Instances {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if len(instance.Msgs) == 0 {
				log.Error(ctx, "No messages in instance", nil, z.Int("i", i))
				return
			}

			duty := core.DutyFromProto(instance.Msgs[0].Msg.Msg.Duty)
			ctx := log.WithCtx(ctx, z.Any("duty", duty))

			log.Info(ctx, "Simulating sniffed consensus",
				z.Int("nodes", int(instance.Nodes)),
				z.Int("msgs", len(instance.Msgs)),
				z.Int("i", i))

			testSniffedInstance(ctx, t, instance)
		})
	}
}

func testSniffedInstance(ctx context.Context, t *testing.T, instance *pbv1.SniffedConsensusInstance) {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	def := newDefinition(int(instance.Nodes), func() []subscriber {
		return []subscriber{func(ctx context.Context, duty core.Duty, value proto.Message) error {
			log.Info(ctx, "Consensus decided", z.Any("value", value))
			cancel()

			return nil
		}}
	})

	recvBuffer := make(chan qbft.Msg[core.Duty, [32]byte], len(instance.Msgs))

	var duty core.Duty
	for _, msg := range instance.Msgs {
		duty = core.DutyFromProto(msg.Msg.Msg.Duty)

		m, err := newMsg(msg.Msg.Msg, msg.Msg.Justification)
		require.NoError(t, err)
		recvBuffer <- m
	}

	// Create a qbft transport from the transport
	qt := qbft.Transport[core.Duty, [32]byte]{
		Broadcast: func(context.Context, qbft.MsgType, core.Duty,
			int64, int64, [32]byte, int64, [32]byte,
			[]qbft.Msg[core.Duty, [32]byte],
		) error {
			return nil
		},
		Receive: recvBuffer,
	}

	// Run the algo, blocking until the context is cancelled.
	err := qbft.Run[core.Duty, [32]byte](ctx, def, qt, duty, instance.PeerIdx, [32]byte{1})
	require.ErrorIs(t, err, context.Canceled)
}

// parseSniffedFile returns a SniffedConsensusSets from a file.
func parseSniffedFile(t *testing.T, path string) *pbv1.SniffedConsensusInstances {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	r, err := gzip.NewReader(bytes.NewBuffer(b))
	require.NoError(t, err)

	b, err = io.ReadAll(r)
	require.NoError(t, err)

	resp := new(pbv1.SniffedConsensusInstances)
	err = proto.Unmarshal(b, resp)
	require.NoError(t, err)

	return resp
}
