// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

const maxQBFTDebugger = 50 * (1 << 20) // 50 MB.

// newQBFTDebugger returns a new qbftDebugger.
func newQBFTDebugger() *qbftDebugger {
	gitHash, _ := version.GitCommit()

	return &qbftDebugger{
		gitHash: gitHash,
	}
}

// qbftDebugger buffers up to 2MB worth of sniffed qbft messages in a fifo buffer serving them as a gzipped
// *pbv1.SniffedConsensusSets protobuf on request.
type qbftDebugger struct {
	gitHash string

	mu        sync.Mutex
	totalSize int
	sets      []*pbv1.SniffedConsensusInstance
}

// AddInstance adds the instance to the fifo buffer, removing older messages if the max size is exceeded.
func (d *qbftDebugger) AddInstance(instance *pbv1.SniffedConsensusInstance) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// getSize returns the size of the proto or false.
	getSize := func(instance *pbv1.SniffedConsensusInstance) (int, bool) {
		b, err := proto.Marshal(instance)
		return len(b), err == nil
	}

	size, ok := getSize(instance)
	if !ok {
		return // Just drop this if we cannot calculate the size
	}

	d.totalSize += size
	d.sets = append(d.sets, instance)

	for d.totalSize > maxQBFTDebugger {
		dropped, _ := getSize(d.sets[0]) // Ignoring ok is ok here since we got the size when we added it.
		d.totalSize -= dropped
		d.sets = d.sets[1:]
	}
}

// ServeHTTP serves sniffed qbft messages in a fifo buffer as a gzipped
// *pbv1.SniffedConsensusSets protobuf.
func (d *qbftDebugger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := d.getZippedProto()
	if err != nil {
		log.Warn(r.Context(), "Error serving qbft debug", err)
		http.Error(w, "something went wrong, see logs", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="qbft_messages.pb.gz"`)
	_, _ = w.Write(b)
}

// getZippedProto returns a gzipped serialised *pbv1.SniffedConsensusSets protobuf of the fifo buffer.
func (d *qbftDebugger) getZippedProto() ([]byte, error) {
	d.mu.Lock()
	b, err := proto.Marshal(&pbv1.SniffedConsensusInstances{
		Instances: d.sets,
		GitHash:   d.gitHash,
	})
	d.mu.Unlock()
	if err != nil {
		return nil, errors.Wrap(err, "marshal proto")
	}

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, errors.Wrap(err, "new gzip writer")
	}

	if _, err := zw.Write(b); err != nil {
		return nil, errors.Wrap(err, "zip proto")
	}

	if err := zw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	return buf.Bytes(), nil
}
