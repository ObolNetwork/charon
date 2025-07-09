// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func TestSignTermsAndConditions(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/termsAndConditions", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Contains(t, r.Header.Get("Authorization"), "Bearer 0x5678")

			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			defer r.Body.Close()

			var req obolapi.RequestSignTermsAndConditions
			require.NoError(t, json.Unmarshal(data, &req))
			require.Equal(t, 1, req.Version)
			require.Equal(t, "user-address", req.Address)
			require.Equal(t, "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273", req.TermsAndConditionsHash)
			require.Equal(t, "0x1234", req.ForkVersion)

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		err = cl.SignTermsAndConditions(t.Context(), "user-address", []byte{0x12, 0x34}, []byte{0x56, 0x78})
		require.NoError(t, err)
	})

	t.Run("marshal error", func(t *testing.T) {
		cl, err := obolapi.New("http://example.com")
		require.NoError(t, err)

		err = cl.SignTermsAndConditions(t.Context(), "user-address", nil, nil)
		require.Error(t, err)
	})

	t.Run("server error response", func(t *testing.T) {
		// Mock server to simulate a server error
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		// Create the client
		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		// Call the function
		err = cl.SignTermsAndConditions(t.Context(), "user-address", []byte{0x12, 0x34}, []byte{0x56, 0x78})
		require.Error(t, err)
	})
}

func TestPublishDefinition(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/definition", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Contains(t, r.Header.Get("Authorization"), "Bearer 0x5678")

			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			defer r.Body.Close()

			var req cluster.Definition
			require.NoError(t, json.Unmarshal(data, &req))
			require.Equal(t, "v1.10.0", req.Version)

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		def := cluster.Definition{
			Version: "v1.10.0",
		}

		err = cl.PublishDefinition(t.Context(), def, []byte{0x56, 0x78})
		require.NoError(t, err)
	})

	t.Run("marshal error", func(t *testing.T) {
		cl, err := obolapi.New("http://example.com")
		require.NoError(t, err)

		// Call the function with an invalid definition to force a marshal error
		var def cluster.Definition

		err = cl.PublishDefinition(t.Context(), def, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal definition")
	})

	t.Run("server error response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		cl, err := obolapi.New(srv.URL)
		require.NoError(t, err)

		def := cluster.Definition{
			Version: "v1.10.0",
		}

		err = cl.PublishDefinition(t.Context(), def, []byte{0x56, 0x78})
		require.Error(t, err)
	})
}
