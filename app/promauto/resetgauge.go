// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promauto

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const separator = "|"

// NewResetGaugeVec creates a new ResetGaugeVec.
func NewResetGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *ResetGaugeVec {
	return &ResetGaugeVec{
		inner:  NewGaugeVec(opts, labelNames),
		labels: make(map[string]bool),
	}
}

// ResetGaugeVec is a GaugeVec that can be reset which deletes all previously set labels.
// This is useful to clear out labels that are no longer present.
type ResetGaugeVec struct {
	inner *prometheus.GaugeVec

	mu     sync.Mutex
	labels map[string]bool
}

func (g *ResetGaugeVec) WithLabelValues(lvs ...string) prometheus.Gauge {
	for _, lv := range lvs {
		if strings.Contains(lv, separator) {
			panic("label value cannot contain separator")
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.labels[strings.Join(lvs, separator)] = true

	return g.inner.WithLabelValues(lvs...)
}

// Reset deletes all previously set labels.
func (g *ResetGaugeVec) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()

	for lv := range g.labels {
		g.inner.DeleteLabelValues(strings.Split(lv, separator)...)
	}

	g.labels = make(map[string]bool)
}
