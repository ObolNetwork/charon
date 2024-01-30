// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

var sniffedFile = flag.String("sniffed-file", "", "path to sniffed file")

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

	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	var expectDecided bool

	def := newDefinition(int(instance.Nodes), func() []subscriber {
		return []subscriber{func(ctx context.Context, duty core.Duty, value proto.Message) error {
			log.Info(ctx, "Consensus decided", z.Any("value", value))
			expectDecided = true
			cancel()

			return nil
		}}
	}, newIncreasingRoundTimer(), func(qcommit []qbft.Msg[core.Duty, [32]byte]) {})

	recvBuffer := make(chan qbft.Msg[core.Duty, [32]byte], len(instance.Msgs))

	var duty core.Duty
	for _, msg := range instance.Msgs {
		if qbft.MsgType(msg.Msg.Msg.Type) == qbft.MsgDecided {
			expectDecided = true
		}

		duty = core.DutyFromProto(msg.Msg.Msg.Duty)

		values, err := valuesByHash(msg.Msg.Values)
		require.NoError(t, err)

		m, err := newMsg(msg.Msg.Msg, msg.Msg.Justification, values)
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
	err := qbft.Run[core.Duty, [32]byte](ctx, def, qt, duty, instance.PeerIdx, qbft.InputValue([32]byte{1}))
	if expectDecided {
		require.ErrorIs(t, err, context.Canceled)
	} else {
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
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
