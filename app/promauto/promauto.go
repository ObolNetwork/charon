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
// that adds support for wrapping all metrics with runtime labels.
package promauto

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Using globals since promauto is designed for use at package initialisation time.
var (
	mu      sync.Mutex
	pending []prometheus.Collector
)

// RegisterAll returns a new registry containing all global pending as well as
// built-in process metrics, it also wraps all the metrics with the provided labels.
func RegisterAll(labels prometheus.Labels) *prometheus.Registry {
	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(labels, registry)
	registerer.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registerer.MustRegister(collectors.NewGoCollector())

	mu.Lock()
	defer mu.Unlock()
	registerer.MustRegister(pending...)

	return registry
}

// addPending adds the collector to the pending registrations.
// It panics if MustRegisterAll was already called.
func addPending(collector ...prometheus.Collector) {
	mu.Lock()
	defer mu.Unlock()

	pending = append(pending, collector...)
}

func NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	c := prometheus.NewGaugeVec(opts, labelNames)
	addPending(c)

	return c
}

func NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	c := prometheus.NewGauge(opts)
	addPending(c)

	return c
}

func NewHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	c := prometheus.NewHistogramVec(opts, labelNames)
	addPending(c)

	return c
}

func NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	c := prometheus.NewHistogram(opts)
	addPending(c)

	return c
}

func NewCounterVec(opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labelNames)
	addPending(c)

	return c
}

func NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	addPending(c)

	return c
}
