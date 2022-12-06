// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	b.bytes += len(entry.Line)
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
