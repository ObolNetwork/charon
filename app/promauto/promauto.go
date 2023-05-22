// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package promauto is a drop-in replacement of github.com/prometheus/client_golang/prometheus/promauto
// and adds support for wrapping all metrics with runtime labels.
package promauto

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/obolnetwork/charon/app/errors"
)

// Using globals since promauto is designed for use at package initialisation time.
var (
	mu      sync.Mutex
	metrics []prometheus.Collector
	metas   []Meta
)

// Meta contains the metadata for a metric.
// This is required because prometheus doesn't expose the metadata of a metric.
type Meta struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	Type      string
	Labels    []string
}

// FQName returns the fully qualified name of the metric.
func (m Meta) FQName() string {
	return prometheus.BuildFQName(m.Namespace, m.Subsystem, m.Name)
}

// GetMetasForT returns all metric metadata that have been
// registered with promauto for testing purposes.
func GetMetasForT(*testing.T) []Meta {
	mu.Lock()
	defer mu.Unlock()

	return metas
}

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
func cacheMetric(metric prometheus.Collector, meta Meta) {
	mu.Lock()
	defer mu.Unlock()

	metrics = append(metrics, metric)
	metas = append(metas, meta)
}

func NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	c := prometheus.NewGaugeVec(opts, labelNames)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help, labelNames...)
	cacheMetric(c, m)

	return c
}

func NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	c := prometheus.NewGauge(opts)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help)
	cacheMetric(c, m)

	return c
}

func NewHistogramVec(opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	c := prometheus.NewHistogramVec(opts, labelNames)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help, labelNames...)
	cacheMetric(c, m)

	return c
}

func NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	c := prometheus.NewHistogram(opts)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help)
	cacheMetric(c, m)

	return c
}

func NewCounterVec(opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labelNames)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help, labelNames...)
	cacheMetric(c, m)

	return c
}

func NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	m := makeMeta(opts, opts.Namespace, opts.Subsystem, opts.Name, opts.Help)
	cacheMetric(c, m)

	return c
}

// makeMeta creates a Meta struct from the provided prometheus metric options.
func makeMeta(typ any, namespace, subsystem, name, help string, labels ...string) Meta {
	typStr := fmt.Sprintf("%T", typ)
	typStr = strings.TrimPrefix(typStr, "prometheus.")
	typStr = strings.TrimSuffix(typStr, "Opts")

	return Meta{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
		Type:      typStr,
		Labels:    labels,
	}
}
