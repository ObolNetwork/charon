// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"bufio"
	"bytes"
	"io"
	"runtime"
	"testing"
	"testing/iotest"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-msgio/pbio"
	"github.com/multiformats/go-varint"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestDelimitedReaderRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 100, initialFrameAlloc - 1, initialFrameAlloc, initialFrameAlloc + 1, 3*initialFrameAlloc + 7, 1 << 20}

	var wire bytes.Buffer

	w := pbio.NewDelimitedWriter(&wire)

	var msgs []*wrapperspb.BytesValue

	for _, size := range sizes {
		msg := wrapperspb.Bytes(bytes.Repeat([]byte{0xAB}, size))
		require.NoError(t, w.WriteMsg(msg))

		msgs = append(msgs, msg)
	}

	// Read the same wire bytes with both pbio and our reader, one byte per Read to exercise growth.
	expect := pbio.NewDelimitedReader(bytes.NewReader(wire.Bytes()), maxMsgSize)
	actual := newDelimitedReader(iotest.OneByteReader(bytes.NewReader(wire.Bytes())), maxMsgSize)

	for _, msg := range msgs {
		e, a := new(wrapperspb.BytesValue), new(wrapperspb.BytesValue)
		require.NoError(t, expect.ReadMsg(e))
		require.NoError(t, actual.ReadMsg(a))
		require.True(t, proto.Equal(msg, a))
		require.True(t, proto.Equal(e, a))
	}

	// Both return io.EOF at a clean end of stream.
	require.ErrorIs(t, expect.ReadMsg(new(wrapperspb.BytesValue)), io.EOF)
	require.ErrorIs(t, actual.ReadMsg(new(wrapperspb.BytesValue)), io.EOF)
}

func TestDelimitedReaderErrors(t *testing.T) {
	t.Run("exceeds max size", func(t *testing.T) {
		r := newDelimitedReader(bytes.NewReader(varint.ToUvarint(101)), 100)
		require.ErrorIs(t, r.ReadMsg(new(wrapperspb.BytesValue)), io.ErrShortBuffer)
	})

	t.Run("relay error passed through", func(t *testing.T) {
		in := io.MultiReader(bytes.NewReader(varint.ToUvarint(100)), bytes.NewReader([]byte{1, 2, 3}), iotest.ErrReader(network.ErrReset))
		err := newDelimitedReader(in, maxMsgSize).ReadMsg(new(wrapperspb.BytesValue))
		require.True(t, IsRelayError(err))
	})
}

// TestDelimitedReaderDeclaredLengthNotAllocated ensures a peer declaring a large frame but sending
// only a few bytes cannot make the reader allocate the declared length.
func TestDelimitedReaderDeclaredLengthNotAllocated(t *testing.T) {
	const declared = 100 << 20 // 100MB

	wire := append(varint.ToUvarint(declared), make([]byte, 10)...)

	buf, err := readFrame(bufio.NewReader(bytes.NewReader(wire)), maxMsgSize)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Len(t, buf, 10)
	require.LessOrEqual(t, cap(buf), initialFrameAlloc)

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	err = newDelimitedReader(bytes.NewReader(wire), maxMsgSize).ReadMsg(new(wrapperspb.BytesValue))

	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20)) // pbio would allocate 100MB here.
}
