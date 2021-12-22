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

// Package middleware overrides the beacon node validator API to enable transparent DV operation.
package middleware

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/rs/zerolog"
)

// Middleware composes the Charon middleware stack.
type Middleware struct {
	Eth2Client   eth2client.Service     // Go client to beacon node
	ValidatorAPI ValidatorProvider      // Go client to beacon node validator APIs
	ReverseProxy *httputil.ReverseProxy // Pass-through reverse proxy of beacon node
	Handler      *Handler               // Middleware override endpoints handler
	Router       *Router                // Sends requests to ReverseProxy or Handler
	Server       *http.Server           // HTTP server
}

// NewMiddleware composes a new middleware stack and creates an unstarted HTTP server.
func NewMiddleware(listenAddr string, beaconURL string, log zerolog.Logger) (*Middleware, error) {
	// Create Eth2 client.
	eth2Client, err := eth2http.New(context.TODO(), eth2http.WithAddress(beaconURL))
	if err != nil {
		return nil, err
	}
	validatorProvider, ok := eth2Client.(ValidatorProvider)
	if !ok {
		return nil, fmt.Errorf("eth2 client does not implement required validator interfaces")
	}
	// Create DVC handler.
	handler := &Handler{ValidatorAPI: validatorProvider}
	restHandler, err := NewRESTHandler(context.TODO(), handler)
	if err != nil {
		return nil, fmt.Errorf("failed to build REST handler for DVC middleware: %w", err)
	}
	// Create upstream.
	beaconURLParsed, err := url.Parse(beaconURL)
	if err != nil {
		return nil, fmt.Errorf("invalid beacon URL: %w", err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(beaconURLParsed)
	// Create router.
	overridePaths := handler.APIPaths()
	basePath := "/eth/v1/"
	router := NewRouter(reverseProxy, restHandler, basePath, overridePaths)
	// Create and start server.
	server := &http.Server{
		Addr:     listenAddr,
		Handler:  router.Mux,
		ErrorLog: stdlog.New(log, "", 0),
	}
	return &Middleware{
		Eth2Client:   eth2Client,
		ValidatorAPI: validatorProvider,
		ReverseProxy: reverseProxy,
		Handler:      handler,
		Router:       router,
		Server:       server,
	}, nil
}

// ListenAndServe starts the HTTP server.
func (m *Middleware) ListenAndServe() error {
	return m.Server.ListenAndServe()
}

// Shutdown stops the HTTP server.
func (m *Middleware) Shutdown(ctx context.Context) error {
	return m.Server.Shutdown(ctx)
}
