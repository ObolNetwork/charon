// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sync

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/testutil"
)

func TestUpdateStep(t *testing.T) {
	sv, err := version.Parse("v0.1")
	require.NoError(t, err)

	server := &Server{
		defHash:   testutil.RandomBytes32(),
		allCount:  1,
		shutdown:  make(map[peer.ID]struct{}),
		connected: make(map[peer.ID]struct{}),
		steps:     make(map[peer.ID]int),
		version:   sv,
	}

	t.Run("wrong initial step", func(t *testing.T) {
		err = server.updateStep("alpha", 100)
		require.ErrorContains(t, err, "peer reported abnormal initial step, expected 0 or 1")
	})

	t.Run("valid peer step update", func(t *testing.T) {
		err = server.updateStep("bravo", 1)
		require.NoError(t, err)

		err = server.updateStep("bravo", 1)
		require.NoError(t, err) // same step is allowed

		err = server.updateStep("bravo", 2)
		require.NoError(t, err) // next step is allowed
	})

	t.Run("peer step is behind", func(t *testing.T) {
		err = server.updateStep("behind", 1)
		require.NoError(t, err)

		err = server.updateStep("behind", 0)
		require.ErrorContains(t, err, "peer reported step is behind the last known step")
	})

	t.Run("peer step is ahead", func(t *testing.T) {
		err = server.updateStep("ahead", 1)
		require.NoError(t, err)

		err = server.updateStep("ahead", 4)
		require.ErrorContains(t, err, "peer reported step is ahead the last known step")
	})
}

func TestReadWriteSizedProto(t *testing.T) {
	t.Run("valid message", func(t *testing.T) {
		msg := &pb.MsgSync{
			Version: "v0.1.0",
			Step:    1,
		}

		var buf bytes.Buffer

		err := writeSizedProto(&buf, msg)
		require.NoError(t, err)

		reader := bytes.NewReader(buf.Bytes())
		result := &pb.MsgSync{}
		err = readSizedProto(reader, result)
		require.NoError(t, err)
		require.Equal(t, msg.GetVersion(), result.GetVersion())
		require.Equal(t, msg.GetStep(), result.GetStep())
	})

	t.Run("size too large", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf[:8], maxMessageSize+1)

		reader := bytes.NewReader(buf)
		result := &pb.MsgSync{}
		err := readSizedProto(reader, result)
		require.ErrorContains(t, err, "invalid message size")
	})

	t.Run("unexpected message length", func(t *testing.T) {
		// Create a buffer with size prefix indicating 100 bytes but only 10 bytes of data
		buf := make([]byte, 8+10)
		binary.LittleEndian.PutUint64(buf[:8], 100)

		reader := bytes.NewReader(buf)
		result := &pb.MsgSync{}
		err := readSizedProto(reader, result)
		require.ErrorContains(t, err, "unexpected message length")
	})
}
