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
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/obolnetwork/charon/api"
	"github.com/obolnetwork/charon/p2p"
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

	srv, err := New(opts.Handler.LocalEnode, opts.Handler.Node, opts.Addr)
	if err != nil {
		return fmt.Errorf("new monitoring server: %w", err)
	}

	log := opts.Log

	// Install shutdown hook.
	go func() {
		<-ctx.Done()
		log.Info().Msg("Shutting down HTTP server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown HTTP server")
		}
	}()

	// Start server and block.
	log.Info().Msgf("Starting HTTP server at %s", opts.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Error().Err(err).Msg("HTTP server failed")
		return err
	}

	return nil
}

func New(localEnode *enode.LocalNode, p2pNode *p2p.Node, addr string) (*http.Server, error) {

	// Set up gRPC-Gateway integrations.
	// TODO(corver): Move this to validatorapi
	handler := Handler{
		LocalEnode: localEnode,
		Node:       p2pNode,
	}
	gmux := gwruntime.NewServeMux()
	if err := api.RegisterControlPlaneHandlerServer(context.TODO(), gmux, handler); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", gmux)
	mux.Handle("/metrics", promhttp.Handler())
	// TODO(corver): Add pprof

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}, nil
}
