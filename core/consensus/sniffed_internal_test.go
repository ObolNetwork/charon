package consensus

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"io"
	"os"
	"testing"
)

var sniffedFile = flag.String("sniffed-file", "/Users/corver/Downloads/qbft_messages.pb.gz", "path to sniffed file")

func TestSniffedFile(t *testing.T) {
	if *sniffedFile == "" {
		t.Skip("no sniffed file provided")
	}

	instances := parseSniffedFile(t, *sniffedFile)
	for i, instance := range instances.Instances {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			testSniffedInstance(t, instance)
		})
	}
}

func testSniffedInstance(t *testing.T, instance *pbv1.SniffedConsensusInstance) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	def := qbft.Definition[core.Duty, [32]byte]{
		// IsLeader is a deterministic leader election function.
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, int(instance.Nodes)) == process
		},
		NewTimer: newRoundTimer,
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			cancel()
		},
		LogUponRule: func(ctx context.Context, _ core.Duty, _, round int64,
			_ qbft.Msg[core.Duty, [32]byte], uponRule string,
		) {
		},
		LogRoundTimeout: func(ctx context.Context, duty core.Duty, process,
			round int64, msgs []qbft.Msg[core.Duty, [32]byte],
		) {
		},
		Nodes:     int(instance.Nodes),
		FIFOLimit: recvBuffer,
	}

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
