// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/stretchr/testify/require"
)

// TestNodeVersionV2Refresh covers a beacon node that reports its execution client only after its
// version was first fetched, e.g. when they start together. The execution client must show up once
// the eth2http service clears its static values cache, without restarting.
func TestNodeVersionV2Refresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var withEE atomic.Bool

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/eth/v1/node/version":
				_, _ = w.Write([]byte(`{"data":{"version":"Lighthouse/v8.0.0"}}`))
			case "/eth/v1/node/syncing":
				_, _ = w.Write([]byte(`{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`))
			case "/eth/v2/node/version":
				ee := ""
				if withEE.Load() {
					ee = `,"execution_client":{"code":"GE","name":"Geth","version":"v1.16.0","commit":"12345678"}`
				}

				_, _ = fmt.Fprintf(w, `{"data":{"beacon_node":{"code":"LH","name":"Lighthouse","version":"v8.0.0","commit":"abcdef01"}%s}}`, ee)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})

		// Serve in-memory, since time in the bubble only advances while no goroutine waits on the network.
		httpCl := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			return rec.Result(), nil
		})}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		cl, err := Instrument([]Client{
			newBeaconClient(ctx, time.Second, [4]byte{}, nil, "http://beacon-node", eth2http.WithHTTPClient(httpCl)),
		}, nil)
		require.NoError(t, err)

		executionClient := func() *apiv1.ClientVersion {
			resp, err := cl.NodeVersionV2(ctx, &eth2api.NodeVersionV2Opts{})
			require.NoError(t, err)

			return resp.Data.ExecutionClient
		}

		require.Nil(t, executionClient())

		withEE.Store(true)
		require.Nil(t, executionClient(), "expected cached version")

		// The eth2http service clears its static values every 5 minutes.
		time.Sleep(5 * time.Minute)
		synctest.Wait()

		ee := executionClient()
		require.NotNil(t, ee, "execution client didn't refresh")
		require.Equal(t, "Geth", ee.Name)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
