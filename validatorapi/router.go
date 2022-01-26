// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package validatorapi defines validator facing API that serves the subset of
// endpoints related to distributed validation and reverse-proxies the rest to the
// upstream beacon client.
package validatorapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	zerologger "github.com/rs/zerolog/log"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var log = zerologger.Logger

// NewRouter returns a new validator http server router. The http router
// translates http requests related to the distributed validator to the validatorapi.Handler.
// All other requests are reserve-proxied to the beacon-node address.
func NewRouter(h Handler, beaconNodeAddr string) (*mux.Router, error) {

	// Register subset of distributed validator related endpoints
	endpoints := []struct {
		Name    string
		Path    string
		Handler handlerFunc
	}{
		{
			Name:    "attester_duties",
			Path:    "/eth/v1/validator/duties/attester/{epoch}",
			Handler: attesterDuties(h),
		},
		{
			Name:    "proposer_duties",
			Path:    "/eth/v1/validator/duties/proposer/{epoch}",
			Handler: proposerDuties(h),
		},
		// TODO(corver): Add more endpoints
	}

	r := mux.NewRouter()
	for _, e := range endpoints {
		r.Handle(e.Path, wrap(e.Name, e.Handler))
	}

	// Everything else is proxied
	proxy, err := proxyHandler(beaconNodeAddr)
	if err != nil {
		return nil, err
	}
	r.PathPrefix("/").Handler(proxy)

	return r, nil
}

// apiErr defines a validator api error that is converted to an eth2 errorResponse.
type apiError struct {
	// StatusCode is the http status code to return, defaults to 500.
	StatusCode int
	// Message is a safe human-readable message, defaults to "Internal server error".
	Message string
	// Err is the original error, returned in debug mode.
	Err error
}

func (a apiError) Error() string {
	return fmt.Sprintf("validator api error[status=%d,msg=%s]: %v", a.StatusCode, a.Message, a.Err)
}

// handlerFunc is a convenient handler function providing a context, parsed path parameters,
// the request body, and returning the response struct or an error.
type handlerFunc func(ctx context.Context, params map[string]string, body []byte) (res interface{}, err error)

// wrap adapts the handler function returning a standard http handler.
// It does tracing, metrics and response and error writing.
func wrap(endpoint string, handler handlerFunc) http.Handler {
	wrap := func(w http.ResponseWriter, r *http.Request) {

		defer observeApiLatency(endpoint)()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, endpoint, err)
			return
		}

		res, err := handler(r.Context(), mux.Vars(r), body)
		if err != nil {
			writeError(w, endpoint, err)
			return
		}

		writeResponse(w, endpoint, res)
	}

	return trace(endpoint, wrap)
}

// trace wraps the passed handler in a OpenTelemetry tracing span.
func trace(endpoint string, handler http.HandlerFunc) http.Handler {
	return otelhttp.NewHandler(handler, "validator."+endpoint)
}

// proposerDuties returns a handler function for the proposer duty endpoint.
func proposerDuties(p eth2client.ProposerDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, body []byte) (interface{}, error) {

		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, err
		}

		// Note the ProposerDutiesProvider interface adds some sugar to the official spec.
		// ValidatorIndices aren't provided over the wire.
		data, err := p.ProposerDuties(ctx, eth2p0.Epoch(epoch), nil)
		if err != nil {
			return nil, err
		}

		return proposerDutiesResponse{
			DependentRoot: eth2p0.Root{}, // TODO(corver): Fill this
			Data:          data,
		}, nil
	}
}

// attesterDuties returns a handler function for the attester duty endpoint.
func attesterDuties(p eth2client.AttesterDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, body []byte) (interface{}, error) {

		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, err
		}

		var req attesterDutiesRequest
		if err := unmarshal(body, &req); err != nil {
			return nil, err
		}

		data, err := p.AttesterDuties(ctx, eth2p0.Epoch(epoch), req)
		if err != nil {
			return nil, err
		}

		return attesterDutiesResponse{
			DependentRoot: eth2p0.Root{}, // TODO(corver): Fill this
			Data:          data,
		}, nil
	}
}

// proxyHandler returns a reverse proxy handler.
func proxyHandler(target string) (http.HandlerFunc, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy target address: %w", err)
	}

	// TODO(corver): Add support for multiple upstream targets via some form of load balancing.
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	return func(w http.ResponseWriter, r *http.Request) {
		defer observeApiLatency("proxy")()
		proxy.ServeHTTP(proxyResponseWriter{w}, r)
	}, nil
}

// writeResponse writes the 200 OK response and json response body.
func writeResponse(w http.ResponseWriter, endpoint string, response interface{}) {
	b, err := json.Marshal(response)
	if err != nil {
		writeError(w, endpoint, fmt.Errorf("marshal response body: %w", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	if _, err = w.Write(b); err != nil {
		// Too late to also try to writeError at this point, so just log.
		log.Error().Err(err).Str("endpoint", endpoint).Msg("Failed writing api response")
	}
}

// writeError writes a http json error response object.
func writeError(w http.ResponseWriter, endpoint string, err error) {
	var aerr apiError
	if !errors.As(err, &aerr) {
		aerr = apiError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Internal server error",
			Err:        err,
		}
	}

	log.Error().Err(err).
		Str("endpoint", endpoint).
		Int("status_code", aerr.StatusCode).
		Str("message", aerr.Message).
		Msg("Validator api error response")
	incApiErrors(endpoint, aerr.StatusCode)

	res := errorResponse{
		Code:    aerr.StatusCode,
		Message: aerr.Message,
		// TODO(corver): Add support for debug mode error and stacktraces.
	}

	b, err2 := json.Marshal(res)
	if err2 != nil {
		log.Error().Err(err2).Msg("Failed marshalling error response")
		// Continue to write nil b.
	}

	w.WriteHeader(aerr.StatusCode)
	w.Header().Set("Content-Type", "application/json")

	if _, err2 = w.Write(b); err2 != nil {
		log.Error().Err(err2).Msg("Failed writing api error")
	}
}

// unmarshal parses the JSON-encoded request body and stores the result
// in the value pointed to by v.
func unmarshal(body []byte, v interface{}) error {
	if len(body) == 0 {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "empty request body",
			Err:        errors.New("empty request body"),
		}
	}

	err := json.Unmarshal(body, v)
	if err != nil {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "failed parsing request body",
			Err:        err,
		}
	}

	return nil
}

// uintParam returns a uint path parameter.
func uintParam(params map[string]string, name string) (uint, error) {
	param := params[name]
	res, err := strconv.ParseUint(param, 10, 64)
	if err != nil {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid uint path parameter %s [%s]", name, param),
			Err:        err,
		}
	}

	return uint(res), nil
}

// proxyResponseWriter wraps a http response writer and instruments errors.
type proxyResponseWriter struct {
	http.ResponseWriter
}

func (w proxyResponseWriter) WriteHeader(statusCode int) {
	if statusCode/100 == 2 {
		// 2XX isn't an error
		return
	}
	incApiErrors("proxy", statusCode)
	w.ResponseWriter.WriteHeader(statusCode)
}
