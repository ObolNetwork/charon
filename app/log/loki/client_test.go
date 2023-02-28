// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
