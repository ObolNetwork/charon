// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"bufio"
	"io"

	"github.com/libp2p/go-msgio/pbio"
	"github.com/multiformats/go-varint"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// initialFrameAlloc is the maximum buffer allocated before any frame bytes are received.
// The buffer then grows (doubling, capped at the declared length) only as bytes arrive.
const initialFrameAlloc = 64 << 10 // 64KB

var _ pbio.ReadCloser = (*delimitedReader)(nil)

// delimitedReader is a drop-in replacement for pbio.NewDelimitedReader that reads the same
// uvarint length-prefixed wire format and returns the same errors, but does not allocate the
// declared frame length up front. This bounds the memory a peer can pin by declaring a large
// length and then sending few bytes.
type delimitedReader struct {
	r       *bufio.Reader
	maxSize int
	closer  io.Closer
}

// newDelimitedReader returns a reader of uvarint length-prefixed protobuf messages of at most maxSize bytes.
func newDelimitedReader(r io.Reader, maxSize int) pbio.ReadCloser {
	d := &delimitedReader{r: bufio.NewReader(r), maxSize: maxSize}
	if c, ok := r.(io.Closer); ok {
		d.closer = c
	}

	return d
}

// ReadMsg reads the next length-prefixed message into msg.
// Like pbio, it returns io.ErrShortBuffer if the declared length exceeds maxSize, and
// returns read errors unwrapped so callers can match them (e.g. IsRelayError).
func (d *delimitedReader) ReadMsg(msg proto.Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic reading message", z.Any("recover", r))
		}
	}()

	buf, err := readFrame(d.r, d.maxSize)
	if err != nil {
		return err
	}

	return proto.Unmarshal(buf, msg) //nolint:wrapcheck // Match pbio error semantics.
}

func (d *delimitedReader) Close() error {
	if d.closer != nil {
		return d.closer.Close()
	}

	return nil
}

// readFrame reads a uvarint length prefix followed by that many bytes.
// It returns the (possibly partial) buffer even on error, for testing allocation bounds.
func readFrame(r *bufio.Reader, maxSize int) ([]byte, error) {
	length64, err := varint.ReadUvarint(r)
	if err != nil {
		return nil, err //nolint:wrapcheck // Match pbio error semantics.
	}

	if length64 > uint64(maxSize) {
		return nil, io.ErrShortBuffer
	}

	return ReadFullIncremental(r, int(length64))
}

// ReadFullIncremental reads exactly size bytes from r, like io.ReadFull, but grows its buffer
// only as bytes arrive instead of allocating size bytes up front. The caller must bound size.
// It returns io.EOF if no bytes were read and io.ErrUnexpectedEOF if EOF is hit part way.
// The partial buffer is returned along with any error.
func ReadFullIncremental(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, 0, min(size, initialFrameAlloc))

	for len(buf) < size {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*cap(buf), size))
			copy(grown, buf)
			buf = grown
		}

		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]

		if len(buf) == size {
			break // Ignore any error returned along with the final bytes, like io.ReadFull.
		}

		if errors.Is(err, io.EOF) {
			if len(buf) == 0 {
				return buf, io.EOF
			}

			return buf, io.ErrUnexpectedEOF
		} else if err != nil {
			return buf, err
		}
	}

	return buf, nil
}
