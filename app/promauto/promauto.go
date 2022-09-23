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

// Package promauto aliases github.com/prometheus/client_golang/prometheus/promauto in order
// to wrap the prometheus.DefaultRegister with runtime labels.
package promauto

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto" //nolint:revive // Only this package may import the original promauto.
)

// defaultRegisterer wraps the original prometheus.defaultRegisterer.
var defaultRegisterer = &wrappingRegisterer{target: prometheus.DefaultRegisterer}

// WrapAndRegister wraps the default register with the provided labels and registers all pending collectors.
func WrapAndRegister(labels prometheus.Labels) {
	defaultRegisterer.WrapAndRegister(labels)
}

type wrappingRegisterer struct {
	target  prometheus.Registerer
	wrapped bool
	mu      sync.Mutex

	pending []prometheus.Collector
}

// WrapAndRegister wraps the default register with the provided labels and registers all pending collectors.
func (r *wrappingRegisterer) WrapAndRegister(labels prometheus.Labels) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Only register once. This is required for testing.
	if r.wrapped {
		return
	}

	if len(labels) > 0 {
		r.target = prometheus.WrapRegistererWith(labels, r.target)
	}

	r.target.MustRegister(r.pending...)
	r.wrapped = true
}

func (r *wrappingRegisterer) MustRegister(collector ...prometheus.Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wrapped {
		panic("wrappingRegisterer already wrapped")
	}

	r.pending = append(r.pending, collector...)
}

func (*wrappingRegisterer) Register(prometheus.Collector) error {
	panic("wrappingRegisterer.Register not supported")
}

func (*wrappingRegisterer) Unregister(prometheus.Collector) bool {
	panic("wrappingRegisterer.Unregister not supported")
}

func NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	return promauto.With(defaultRegisterer).NewGaugeVec(opts, labelNames)
}

func NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	return promauto.With(defaultRegisterer).NewGauge(opts)
}

func NewHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	return promauto.With(defaultRegisterer).NewHistogramVec(opts, labelNames)
}

func NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	return promauto.With(defaultRegisterer).NewHistogram(opts)
}

func NewCounterVec(opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	return promauto.With(defaultRegisterer).NewCounterVec(opts, labelNames)
}

func NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	return promauto.With(defaultRegisterer).NewCounter(opts)
}
