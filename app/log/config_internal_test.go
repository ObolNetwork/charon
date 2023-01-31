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

package log

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
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
		t.Run(fmt.Sprint(i), func(t *testing.T) {
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
		require.Len(t, req.Streams, 1)
		require.Len(t, req.Streams[0].Entries, 1)
		// Assert caller is this file.
		require.Contains(t, req.Streams[0].Entries[0].String(), "caller=log/config_internal_test.go:")
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

func decode(t *testing.T, b []byte) *pbv1.PushRequest {
	t.Helper()

	pb, err := snappy.Decode(nil, b)
	require.NoError(t, err)

	resp := new(pbv1.PushRequest)
	require.NoError(t, proto.Unmarshal(pb, resp))

	return resp
}
