// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

// TestLockPublish tests.
func TestLockPublish(t *testing.T) {
	ctx := context.Background()

	t.Run("2xx response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Path, "/lock")
			require.Equal(t, r.Header.Get("Content-Type"), "application/json")

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
				d.TargetGasLimit = 0
			},
		}

		seed := 0
		random := rand.New(rand.NewSource(int64(seed)))
		lock, _, _ := cluster.NewForT(t, 3, 3, 4, seed, random, opts...)

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)
		err = cl.PublishLock(ctx, lock)
		require.NoError(t, err)
	})
}

func TestURLParsing(t *testing.T) {
	t.Run("invalid url", func(t *testing.T) {
		cl, err := obolapi.New("badURL")
		require.Error(t, err)
		require.Empty(t, cl)
	})

	t.Run("http url", func(t *testing.T) {
		cl, err := obolapi.New("http://unsafe.today")
		require.NoError(t, err)
		require.NotEmpty(t, cl)
	})

	t.Run("https url", func(t *testing.T) {
		cl, err := obolapi.New("https://safe.today")
		require.NoError(t, err)
		require.NotEmpty(t, cl)
	})
}

func TestLaunchpadDashURL(t *testing.T) {
	t.Run("produced url is what we expect", func(t *testing.T) {
		cl, err := obolapi.New("https://safe.today")
		require.NoError(t, err)
		require.NotEmpty(t, cl)

		result := cl.LaunchpadURLForLock(cluster.Lock{LockHash: bytes.Repeat([]byte{0x42}, 32)})

		require.NotEmpty(t, result)

		parsedRes := testutil.MustParseRequestURI(t, result)

		require.Equal(t, "safe.today", parsedRes.Host)
		require.Equal(
			t,
			"/lock/0x4242424242424242424242424242424242424242424242424242424242424242/launchpad",
			parsedRes.Path,
		)
	})
}
