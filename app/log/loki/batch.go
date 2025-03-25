// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package loki

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang/snappy"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	pbv1 "github.com/obolnetwork/charon/app/log/loki/lokipb/v1"
)

// batch holds pending log streams waiting to be sent to Loki, and it's used
// to reduce the number of push requests to Loki aggregating multiple
// entries in a single batch request.
type batch struct {
	entries   []*pbv1.Entry
	bytes     int
	createdAt time.Time
}

func newBatch(entries ...*pbv1.Entry) *batch {
	b := &batch{
		createdAt: time.Now(),
	}

	for _, entry := range entries {
		b.Add(entry)
	}

	return b
}

// Add an entry to the batch.
func (b *batch) Add(entry *pbv1.Entry) {
	b.bytes += len(entry.GetLine())
	b.entries = append(b.entries, entry)
}

// Size returns the current batch size in bytes.
func (b batch) Size() int {
	return b.bytes
}

// Age of the batch since its creation.
func (b batch) Age() time.Duration {
	return time.Since(b.createdAt)
}

// Encode the batch as snappy-compressed push request, and returns
// the encoded bytes and the number of encoded entries.
func (b batch) Encode(labels map[string]string) ([]byte, error) {
	buf, err := proto.Marshal(&pbv1.PushRequest{
		Streams: []*pbv1.Stream{{
			Labels:  fmtLabels(labels),
			Entries: b.entries,
		}},
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal loki proto")
	}

	return snappy.Encode(nil, buf), nil
}

// fmtLabels returns the labels map as formatted string.
func fmtLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}

	var resp []string
	for k, v := range labels {
		resp = append(resp, fmt.Sprintf(`%s="%s"`, k, v))
	}

	return "{" + strings.Join(resp, ",") + "}"
}
