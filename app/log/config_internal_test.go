// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:revive,nolintlint // somehow the nolintlint linter catches revive as unnecessary, while it is
package log

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/proto"

	pbv1 "github.com/obolnetwork/charon/app/log/loki/lokipb/v1"
)

func TestFormatZapTest(t *testing.T) {
	tests := []struct {
		Input  string
		Output string
	}{
		{
			Input: `github.com/obolnetwork/charon/app/log_test.TestErrorWrap
	/Users/corver/repos/charon/app/log/log_test.go:57
testing.tRunner
	/opt/homebrew/Cellar/go/1.17.6/libexec/src/testing/testing.go:1259`,
			Output: "	app/log/log_test.go:57 .TestErrorWrap",
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual := formatZapStack(test.Input)
			require.Equal(t, test.Output, actual)
		})
	}
}

func TestLokiCaller(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		req := decode(t, b)
		require.Len(t, req.GetStreams(), 1)
		require.Len(t, req.GetStreams()[0].GetEntries(), 1)
		// Assert caller is this file.
		require.Contains(t, req.GetStreams()[0].GetEntries()[0].String(), "caller=log/config_internal_test.go:")
		close(done)
	}))

	SetLokiLabels(nil)

	err := InitLogger(Config{
		Level:         "info",
		Format:        "console",
		LokiAddresses: []string{srv.URL},
		LokiService:   "test",
	})
	require.NoError(t, err)

	Info(context.Background(), "test")
	<-done
}

var initForTFuncs = map[string]func(*testing.T, zapcore.WriteSyncer, ...func(*zapcore.EncoderConfig)){
	"console": InitConsoleForT,
	"logfmt":  InitLogfmtForT,
	"json":    InitJSONForT,
}

func TestInitForTRestoresLogger(t *testing.T) {
	for name, initFunc := range initForTFuncs {
		t.Run(name, func(t *testing.T) {
			var buf zaptest.Buffer

			t.Run("install", func(t *testing.T) {
				initFunc(t, &buf)
				Debug(context.Background(), "inside test")
				require.Contains(t, buf.String(), "inside test")
			})

			// The previous logger must be restored on test cleanup,
			// so this log must not be written to the buffer.
			lenBefore := buf.Len()

			Debug(context.Background(), "after test")
			require.Equal(t, lenBefore, buf.Len())
		})
	}
}

func TestInitForTConcurrentLogging(t *testing.T) {
	for name, initFunc := range initForTFuncs {
		t.Run(name, func(t *testing.T) {
			// zaptest.Buffer is not safe for concurrent use, the
			// initialisers must synchronise writes to it.
			var buf zaptest.Buffer

			initFunc(t, &buf)

			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					for range 100 {
						Debug(context.Background(), "concurrent log")
					}
				})
			}

			wg.Wait()
		})
	}
}

func decode(t *testing.T, b []byte) *pbv1.PushRequest {
	t.Helper()

	pb, err := snappy.Decode(nil, b)
	require.NoError(t, err)

	resp := new(pbv1.PushRequest)
	require.NoError(t, proto.Unmarshal(pb, resp))

	return resp
}
