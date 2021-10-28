/*
Copyright © 2021 Obol Technologies Inc.
Copyright © 2020, 2021 Attestant Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"github.com/obolnetwork/charon/internal/services/monitoring"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var metricsNamespace = "charon"

var releaseMetric *prometheus.GaugeVec
var readyMetric prometheus.Gauge

func registerMetrics(ctx context.Context, monitor monitoring.Service) error {
	if releaseMetric != nil {
		// Already registered.
		return nil
	}
	if monitor == nil {
		// No monitor.
		return nil
	}
	switch monitor.Presenter() {
	case "prometheus":
		return registerPrometheusMetrics(ctx)
	case "null":
		log.Debug().Msg("no metrics will be generated for this module")
	}
	return nil
}

func registerPrometheusMetrics(ctx context.Context) error {
	startTime := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "start_time_secs",
		Help:      "The timestamp at which this instance started.",
	})
	if err := prometheus.Register(startTime); err != nil {
		return errors.Wrap(err, "failed to regsiter start_time_secs")
	}
	startTime.SetToCurrentTime()

	releaseMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "release",
		Help:      "The release of this instance.",
	}, []string{"version"})
	if err := prometheus.Register(releaseMetric); err != nil {
		return err
	}

	readyMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "ready",
		Help:      "1 if ready to serve requests, otherwise 0.",
	})
	if err := prometheus.Register(readyMetric); err != nil {
		return errors.Wrap(err, "failed to regsiter ready")
	}

	return nil
}

// SetRelease is called when the release version is established.
func setRelease(ctx context.Context, version string) {
	if releaseMetric == nil {
		return
	}

	releaseMetric.WithLabelValues(version).Set(1)
}

func setReady(ctx context.Context, ready bool) {
	if readyMetric == nil {
		return
	}

	if ready {
		readyMetric.Set(1)
	} else {
		readyMetric.Set(0)
	}
}
