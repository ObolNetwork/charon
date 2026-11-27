// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"bufio"
	"bytes"
	"fmt"
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

	"github.com/obolnetwork/charon/app/errors"
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

// FuzzDelimitedReader ensures newDelimitedReader returns the same messages and errors as pbio for any input.
func FuzzDelimitedReader(f *testing.F) {
	const maxSize = 64 << 10 // Small, since pbio allocates the declared length on every input.

	frame := func(size int) []byte {
		b, err := proto.Marshal(wrapperspb.Bytes(bytes.Repeat([]byte{0xAB}, size)))
		require.NoError(f, err)

		return append(varint.ToUvarint(uint64(len(b))), b...)
	}

	f.Add([]byte{})
	f.Add(frame(0))
	f.Add(frame(100))
	f.Add(append(frame(1), frame(1000)...))
	f.Add(frame(maxSize - 4))                           // Declared length maxSize.
	f.Add(append(varint.ToUvarint(maxSize+1), 1, 2, 3)) // Declared length exceeds maxSize.
	f.Add(append(varint.ToUvarint(1<<62), 1, 2, 3))     // Huge declared length.
	f.Add(frame(1000)[:500])                            // Truncated body.
	f.Add(varint.ToUvarint(10))                         // Length only.
	f.Add(bytes.Repeat([]byte{0xFF}, 11))               // Overlong varint.

	f.Fuzz(func(t *testing.T, data []byte) {
		expect := pbio.NewDelimitedReader(bytes.NewReader(data), maxSize)
		actual := newDelimitedReader(iotest.HalfReader(bytes.NewReader(data)), maxSize)

		for {
			e, a := new(wrapperspb.BytesValue), new(wrapperspb.BytesValue)

			errE, errA := expect.ReadMsg(e), actual.ReadMsg(a)
			if errE != nil {
				require.Error(t, errA)

				for _, sentinel := range []error{io.EOF, io.ErrUnexpectedEOF, io.ErrShortBuffer} {
					require.Equal(t, errors.Is(errE, sentinel), errors.Is(errA, sentinel), "expect=%v actual=%v", errE, errA)
				}

				return
			}

			require.NoError(t, errA)
			require.True(t, proto.Equal(e, a))
		}
	})
}

// BenchmarkDelimitedReader compares newDelimitedReader against pbio for typical message sizes,
// reading one frame per new reader as each received stream does.
func BenchmarkDelimitedReader(b *testing.B) {
	readers := []struct {
		name string
		new  func(io.Reader) pbio.Reader
	}{
		{"pbio", func(r io.Reader) pbio.Reader { return pbio.NewDelimitedReader(r, maxMsgSize) }},
		{"incremental", func(r io.Reader) pbio.Reader { return newDelimitedReader(r, maxMsgSize) }},
	}

	for _, size := range []int{256, 4 << 10, 64 << 10, 1 << 20} {
		var wire bytes.Buffer
		require.NoError(b, pbio.NewDelimitedWriter(&wire).WriteMsg(wrapperspb.Bytes(make([]byte, size))))

		for _, reader := range readers {
			b.Run(fmt.Sprintf("%s/%d", reader.name, size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(wire.Len()))

				for b.Loop() {
					err := reader.new(bytes.NewReader(wire.Bytes())).ReadMsg(new(wrapperspb.BytesValue))
					require.NoError(b, err)
				}
			})
		}
	}
}
