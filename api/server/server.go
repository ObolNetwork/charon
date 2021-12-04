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

// Package server implements the internal server.
package server

import (
	"context"
	"net/http"
	"time"

	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/obolnetwork/charon/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// Options contains the server options.
type Options struct {
	Addr    string   // address exposing REST API
	Handler *Handler // gRPC handler

	Log zerolog.Logger
}

// Run starts the internal server and blocks until a fatal error occurs or the context is canceled.
func Run(ctx context.Context, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log := opts.Log

	// Set up endpoints.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	// Set up gRPC-Gateway integrations.
	gmux := gwruntime.NewServeMux()
	if err := api.RegisterControlPlaneHandlerServer(ctx, gmux, opts.Handler); err != nil {
		return err
	}
	mux.Handle("/", gmux)

	s := &http.Server{
		Addr:    opts.Addr,
		Handler: mux,
	}
	// Install shutdown hook.
	go func() {
		<-ctx.Done()
		log.Info().Msg("Shutting down HTTP server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown HTTP server")
		}
	}()
	// Start server and block.
	log.Info().Msgf("Starting HTTP server at %s", opts.Addr)
	if err := s.ListenAndServe(); err != http.ErrServerClosed {
		log.Error().Err(err).Msg("HTTP server failed")
		return err
	}
	return nil
}
