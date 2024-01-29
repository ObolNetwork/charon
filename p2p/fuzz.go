// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	fuzz "github.com/google/gofuzz"
	"github.com/libp2p/go-msgio/pbio"
	"google.golang.org/protobuf/proto"
)

var (
	_ pbio.Reader = fuzzReaderWriter{}
	_ pbio.Writer = fuzzReaderWriter{}
)

// fuzzReaderWriter implements the pbio.Reader and pbio.Writer interfaces and provides functionality
// for reading and writing messages with fuzzed data.
type fuzzReaderWriter struct {
	w pbio.Writer
}

// ReadMsg fuzzes the received message, and stores the fuzzed data in the provided `msg` argument.
func (fuzzReaderWriter) ReadMsg(msg proto.Message) error {
	fuzz.New().Fuzz(msg)

	return nil
}

// WriteMsg writes the fuzzed message using the associated writer.
func (f fuzzReaderWriter) WriteMsg(msg proto.Message) error {
	cloneMsg := proto.Clone(msg)
	fuzz.New().Fuzz(cloneMsg)

	return f.w.WriteMsg(cloneMsg)
}
