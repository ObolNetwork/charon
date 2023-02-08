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

package launchpad_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/launchpad"
)

func TestLockPublish(t *testing.T) {
	ctx := context.Background()

	t.Run("2xx response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Path, "/lock")

			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			defer r.Body.Close()

			var req cluster.Lock
			require.NoError(t, json.Unmarshal(data, &req))
			require.Equal(t, req.Version, "v1.5.0")

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		opts := []func(d *cluster.Definition){
			func(d *cluster.Definition) {
				d.Version = "v1.5.0"
			},
		}

		lock, _, _ := cluster.NewForT(t, 3, 3, 4, 0, opts...)

		cl := launchpad.New(srv.URL)
		err := cl.PublishLock(ctx, lock)
		require.NoError(t, err)
	})

	t.Run("version not supported", func(t *testing.T) {
		lock, _, _ := cluster.NewForT(t, 3, 3, 4, 0)

		cl := launchpad.New("")
		err := cl.PublishLock(ctx, lock)
		require.ErrorContains(t, err, "version not supported")
	})
}
