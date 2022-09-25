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

// Package promauto is a drop-in replacement of github.com/prometheus/client_golang/prometheus/promauto
// and adds support for wrapping all metrics with runtime labels.
package promauto

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/obolnetwork/charon/app/errors"
)

// Using globals since promauto is designed for use at package initialisation time.
var (
	mu      sync.Mutex
	metrics []prometheus.Collector
)

// NewRegistry returns a new registry containing all promauto created metrics and
// built-in Go process metrics wrapping everything with the provided labels.
func NewRegistry(labels prometheus.Labels) (*prometheus.Registry, error) {
	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(labels, registry)

	err := registerer.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err != nil {
		return nil, errors.Wrap(err, "register process collector")
	}

	err = registerer.Register(collectors.NewGoCollector())
	if err != nil {
		return nil, errors.Wrap(err, "register go collector")
	}

	mu.Lock()
	defer mu.Unlock()

	for _, metric := range metrics {
		err = registerer.Register(metric)
		if err != nil {
			return nil, errors.Wrap(err, "register metric")
		}
	}

	return registry, nil
}

// cacheMetric adds the metric to the local global cache.
func cacheMetric(metric prometheus.Collector) {
	mu.Lock()
	defer mu.Unlock()

	metrics = append(metrics, metric)
}

func NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	c := prometheus.NewGaugeVec(opts, labelNames)
	cacheMetric(c)

	return c
}

func NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	c := prometheus.NewGauge(opts)
	cacheMetric(c)

	return c
}

func NewHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	c := prometheus.NewHistogramVec(opts, labelNames)
	cacheMetric(c)

	return c
}

func NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	c := prometheus.NewHistogram(opts)
	cacheMetric(c)

	return c
}

func NewCounterVec(opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labelNames)
	cacheMetric(c)

	return c
}

func NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	cacheMetric(c)

	return c
}
