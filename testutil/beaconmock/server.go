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

package beaconmock

import (
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

//go:embed static.json
var staticJSON []byte

// HTTPMock defines the endpoints served by the beacon API mock http server.
// It serves all proxied endpoints not handled by charon's validatorapi.
// Endpoints include static endpoints defined in static.json and a few stubbed paths.
type HTTPMock interface {
	eth2client.BeaconCommitteesProvider
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeSyncingProvider
	eth2client.NodeVersionProvider
	eth2client.SlotDurationProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.SyncCommitteeDutiesProvider
}

// staticOverride defines a http server static override for a endpoint response value.
type staticOverride struct {
	Endpoint string
	Key      string
	Value    string
}

// newHTTPServer returns a beacon API mock http server.
func newHTTPServer(addr string, overrides ...staticOverride) (*http.Server, error) {
	debug := os.Getenv("BEACONMOCK_DEBUG") == "true" // NOTE: These logs are verbose, so disabled by default.
	shutdown := make(chan struct{})

	endpoints := []struct {
		Path    string
		Handler http.HandlerFunc
	}{
		{
			Path:    "/up", // Can be used to test if server is up.
			Handler: func(w http.ResponseWriter, r *http.Request) {},
		},
		{
			Path:    "/eth/v1/validator/beacon_committee_subscriptions",
			Handler: func(w http.ResponseWriter, r *http.Request) {},
		},
		{
			Path: "/eth/v1/validator/duties/sync/{epoch}",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data":[]}`))
			},
		},
		{
			Path: "/eth/v1/validator/aggregate_attestation",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code": 403,"message": "Beacon node was not assigned to aggregate on that subnet."}`))
			},
		},
		{
			Path: "/eth/v1/node/version",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data": {"version": "charon/static_beacon_mock"}}`))
			},
		},
		{
			Path: "/eth/v1/node/syncing",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data": {"head_slot": "1","sync_distance": "0","is_syncing": false}}`))
			},
		},
		{
			Path: "/eth/v1/beacon/headers/head",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data": {"header": {"message": {"slot": "1"}}}}`))
			},
		},
		{
			Path: "/eth/v1/events",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				// TODO(corver): Send keep alives
				select {
				case <-shutdown:
				case <-r.Context().Done():
				}
			},
		},
	}

	r := mux.NewRouter()

	// Configure above endpoints.
	for _, e := range endpoints {
		e := e
		r.Handle(e.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithTopic(r.Context(), "bmock")
			ctx = log.WithCtx(ctx, z.Str("path", e.Path))
			if debug {
				log.Debug(ctx, "Serving mocked endpoint")
			}
			e.Handler(w, r)
		}))
	}

	// Configure static endpoints.
	staticResponses := make(map[string]json.RawMessage)
	err := json.Unmarshal(staticJSON, &staticResponses)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal static json")
	}

	// Apply overrides
	for _, override := range overrides {
		response, err := overrideResponse(staticResponses[override.Endpoint], override.Key, override.Value)
		if err != nil {
			return nil, err
		}
		staticResponses[override.Endpoint] = response
	}

	r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := log.WithTopic(r.Context(), "bmock")
		ctx = log.WithCtx(ctx, z.Str("path", r.URL.Path))

		resp, ok := staticResponses[r.URL.Path]
		if !ok {
			log.Warn(ctx, "Unsupported path", nil)
			w.WriteHeader(http.StatusNotFound)

			return
		}
		if debug {
			log.Debug(ctx, "Serving static endpoint")
		}
		_, _ = w.Write(resp)
	}))

	s := http.Server{Addr: addr, Handler: r}
	s.RegisterOnShutdown(func() {
		close(shutdown)
	})

	return &s, nil
}

// newHTTPMock starts and returns a static beacon mock http server and client.
func newHTTPMock(overrides ...staticOverride) (HTTPMock, *http.Server, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, errors.Wrap(err, "listen")
	}

	srv, err := newHTTPServer(l.Addr().String(), overrides...)
	if err != nil {
		return nil, nil, err
	}

	go func() {
		err = srv.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	addr := "http://" + srv.Addr

	// Wait for server to be up
	for {
		resp, err := http.Get(addr + "/up")
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	// Connect eth2http client.
	cl, err := eth2http.New(context.Background(), eth2http.WithLogLevel(1), eth2http.WithAddress(addr))
	if err != nil {
		return nil, nil, errors.Wrap(err, "new http client")
	}

	return cl.(HTTPMock), srv, nil
}

// overrideResponse overrides the key in the raw response. If key is empty, it overrides the whole response.
func overrideResponse(rawResponse json.RawMessage, key, value string) (json.RawMessage, error) {
	if key == "" {
		return []byte(value), nil
	}

	response := struct {
		Data map[string]string `json:"data"`
	}{
		Data: map[string]string{},
	}
	if err := json.Unmarshal(rawResponse, &response); err != nil {
		return nil, errors.Wrap(err, "unmarshal spec")
	}

	response.Data[key] = value

	rawResult, err := json.Marshal(response)
	if err != nil {
		return nil, errors.Wrap(err, "marshal spec")
	}

	return rawResult, nil
}
