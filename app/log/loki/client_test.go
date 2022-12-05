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

package loki_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log/loki"
	pbv1 "github.com/obolnetwork/charon/app/log/loki/lokipb/v1"
)

func TestLoki(t *testing.T) {
	const (
		serviceLabel    = "test"
		otherLabelKey   = "k"
		otherLabelValue = "v"
	)

	received := make(chan string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		req := decode(t, b)
		require.Len(t, req.Streams, 1)
		require.Contains(t, req.Streams[0].Labels, fmt.Sprintf(`service="%s"`, serviceLabel))
		require.Contains(t, req.Streams[0].Labels, fmt.Sprintf(`%s="%s"`, otherLabelKey, otherLabelValue))
		for _, entry := range req.Streams[0].Entries {
			received <- entry.Line
		}
	}))

	// Only return lazy labels after 3 attempts.
	var count int
	lazyLabels := func() (map[string]string, bool) {
		count++
		if count < 3 {
			return nil, false
		}

		return map[string]string{
			otherLabelKey: otherLabelValue,
		}, true
	}

	cl := loki.NewForT(srv.URL, serviceLabel, time.Millisecond, 1024, lazyLabels)

	const n = 4

	go cl.Run()

	for i := 0; i < n; i++ {
		cl.Add(fmt.Sprint(i))
	}

	for i := 0; i < n; i++ {
		require.Equal(t, fmt.Sprint(i), <-received)
	}

	cl.Stop(context.Background())
}

func decode(t *testing.T, b []byte) *pbv1.PushRequest {
	t.Helper()

	pb, err := snappy.Decode(nil, b)
	require.NoError(t, err)

	resp := new(pbv1.PushRequest)
	require.NoError(t, proto.Unmarshal(pb, resp))

	return resp
}
