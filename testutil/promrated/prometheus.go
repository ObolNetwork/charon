// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
)

// serveMonitoring creates a liveness endpoint and serves metrics to prometheus.
func serveMonitoring(addr string, registry *prometheus.Registry) error {
	mux := http.NewServeMux()

	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	))

	server := http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}

	return errors.Wrap(server.ListenAndServe(), "failed to serve prometheus metrics")
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
