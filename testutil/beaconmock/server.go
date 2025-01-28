// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/testutil"
)

//go:embed static.json
var staticJSON []byte

// HTTPMock defines the endpoints served by the beacon API mock http server.
// It serves all proxied endpoints not handled by charon's validatorapi.
// Endpoints include static endpoints defined in static.json and a few stubbed paths.
type HTTPMock interface {
	eth2client.BeaconBlockRootProvider
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.EventsProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeSyncingProvider
	eth2client.NodeVersionProvider
	eth2client.SlotDurationProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.SyncCommitteeSubscriptionsSubmitter
}

// staticOverride defines a http server static override for a endpoint response value.
type staticOverride struct {
	Endpoint string
	Key      string
	Value    string
}

// newHTTPServer returns a beacon API mock http server.
func newHTTPServer(addr string, optionalHandlers map[string]http.HandlerFunc, overrides ...staticOverride,
) (*http.Server, error) {
	debug := os.Getenv("BEACONMOCK_DEBUG") == "true" // NOTE: These logs are verbose, so disabled by default.
	shutdown := make(chan struct{})

	endpoints := map[string]http.HandlerFunc{
		"/up": func(http.ResponseWriter, *http.Request) {
			// Can be used to test if server is up.
		},
		"/eth/v1/validator/sync_committee_subscriptions": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
		"/eth/v2/validator/aggregate_attestation": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code": 403,"message": "Beacon node was not assigned to aggregate on that subnet."}`))
		},
		"/eth/v1/validator/beacon_committee_subscriptions": func(http.ResponseWriter, *http.Request) {
		},
		"/eth/v1/node/version": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data": {"version": "charon/static_beacon_mock"}}`))
		},
		"/eth/v1/node/syncing": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data": {"head_slot": "1","sync_distance": "0","is_syncing": false}}`))
		},
		"/eth/v1/beacon/headers/head": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data": {"header": {"message": {"slot": "1"}}}}`))
		},
		"/eth/v1/validator/prepare_beacon_proposer": func(http.ResponseWriter, *http.Request) {
		},
		"/eth/v1/events": func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-shutdown:
			case <-r.Context().Done():
			}
		},
		"/eth/v2/beacon/blocks/{block_id}": func(w http.ResponseWriter, _ *http.Request) {
			type signedBlockResponseJSON struct {
				Version *eth2spec.DataVersion        `json:"version"`
				Data    *bellatrix.SignedBeaconBlock `json:"data"`
			}

			version := eth2spec.DataVersionBellatrix
			resp, err := json.Marshal(signedBlockResponseJSON{
				Version: &version,
				Data:    testutil.RandomBellatrixSignedBeaconBlock(),
			})
			if err != nil {
				panic(err) // This should never happen and this is test code sorry ;)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(resp)
		},
	}

	for path, handler := range optionalHandlers {
		endpoints[path] = handler
	}

	r := mux.NewRouter()

	// Configure above endpoints.
	for path, handler := range endpoints {
		r.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithTopic(r.Context(), "bmock")
			ctx = log.WithCtx(ctx, z.Str("path", path))
			if debug {
				log.Debug(ctx, "Serving mocked endpoint")
			}
			handler(w, r)
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

	s := http.Server{Addr: addr, Handler: r, ReadHeaderTimeout: time.Second}
	s.RegisterOnShutdown(func() {
		close(shutdown)
	})

	return &s, nil
}

// newHTTPMock starts and returns a static beacon mock http server and client.
func newHTTPMock(optionalHandlers map[string]http.HandlerFunc, overrides ...staticOverride) (HTTPMock, *http.Server, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, errors.Wrap(err, "listen")
	}

	srv, err := newHTTPServer(l.Addr().String(), optionalHandlers, overrides...)
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
		resp, err := http.Get(addr + "/up") //nolint:noctx // Non-critical code
		_ = resp.Body.Close()
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

	httpMock, ok := cl.(HTTPMock)
	if !ok {
		return nil, nil, errors.New("type assert http mock")
	}

	return httpMock, srv, nil
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
