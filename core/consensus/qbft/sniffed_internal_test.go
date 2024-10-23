// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/utils"
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
		z.Int("instances", len(instances.GetInstances())),
		z.Str("git_hash", instances.GetGitHash()),
	)

	for i, instance := range instances.GetInstances() {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if len(instance.GetMsgs()) == 0 {
				log.Error(ctx, "No messages in instance", nil, z.Int("i", i))
				return
			}

			duty := core.DutyFromProto(instance.GetMsgs()[0].GetMsg().GetMsg().GetDuty())
			ctx := log.WithCtx(ctx, z.Any("duty", duty))

			log.Info(ctx, "Simulating sniffed consensus",
				z.Int("nodes", int(instance.GetNodes())),
				z.Int("msgs", len(instance.GetMsgs())),
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

	def := newDefinition(int(instance.GetNodes()), func() []subscriber {
		return []subscriber{func(ctx context.Context, duty core.Duty, value proto.Message) error {
			log.Info(ctx, "Consensus decided", z.Any("value", value))
			expectDecided = true
			cancel()

			return nil
		}}
	}, utils.NewIncreasingRoundTimer(), func(qcommit []qbft.Msg[core.Duty, [32]byte]) {})

	recvBuffer := make(chan qbft.Msg[core.Duty, [32]byte], len(instance.GetMsgs()))

	var duty core.Duty
	for _, msg := range instance.GetMsgs() {
		if qbft.MsgType(msg.GetMsg().GetMsg().GetType()) == qbft.MsgDecided {
			expectDecided = true
		}

		duty = core.DutyFromProto(msg.GetMsg().GetMsg().GetDuty())

		values, err := valuesByHash(msg.GetMsg().GetValues())
		require.NoError(t, err)

		m, err := newMsg(msg.GetMsg().GetMsg(), msg.GetMsg().GetJustification(), values)
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
	err := qbft.Run[core.Duty, [32]byte](ctx, def, qt, duty, instance.GetPeerIdx(), qbft.InputValue([32]byte{1}))
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
