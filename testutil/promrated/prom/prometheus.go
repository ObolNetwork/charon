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

package prom

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/log"
)

func ListenAndServe(ctx context.Context, addr string) {
	// Healthz handler used in Kubernetes set-ups to automatically restart
	// the container in case something goes off.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Prometheus handler to expose metrics to prometheus.
	http.Handle("/metrics", promhttp.Handler())

	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Error(ctx, "Failed to serve Prom Metrics", err)
	}
}
