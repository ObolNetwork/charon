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
)

// defaultRegisterer wraps the original prometheus.defaultRegisterer.
var defaultRegisterer = &wrappingRegisterer{target: prometheus.DefaultRegisterer}

// WrapAndRegister wraps the default register with the provided labels and registers all pending collectors.
func WrapAndRegister(labels prometheus.Labels) {
	defaultRegisterer.WrapAndRegister(labels)
}

type wrappingRegisterer struct {
	mu      sync.Mutex
	target  prometheus.Registerer
	pending []prometheus.Collector
	wrapped bool
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

// MustRegister implements prometheus.Registerer.
func (r *wrappingRegisterer) MustRegister(collector ...prometheus.Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wrapped {
		panic("wrappingRegisterer already wrapped")
	}

	r.pending = append(r.pending, collector...)
}

// Register implements prometheus.Registerer.
func (*wrappingRegisterer) Register(prometheus.Collector) error {
	panic("wrappingRegisterer.Register not supported")
}

// Unregister implements prometheus.Registerer.
func (*wrappingRegisterer) Unregister(prometheus.Collector) bool {
	panic("wrappingRegisterer.Unregister not supported")
}

func NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	c := prometheus.NewGaugeVec(opts, labelNames)
	defaultRegisterer.MustRegister(c)

	return c
}

func NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	c := prometheus.NewGauge(opts)
	defaultRegisterer.MustRegister(c)

	return c
}

func NewHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	c := prometheus.NewHistogramVec(opts, labelNames)
	defaultRegisterer.MustRegister(c)

	return c
}

func NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	c := prometheus.NewHistogram(opts)
	defaultRegisterer.MustRegister(c)

	return c
}

func NewCounterVec(opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labelNames)
	defaultRegisterer.MustRegister(c)

	return c
}

func NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	defaultRegisterer.MustRegister(c)

	return c
}
