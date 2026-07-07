// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promauto

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// NewResetGaugeVec creates a new ResetGaugeVec.
func NewResetGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *ResetGaugeVec {
	return &ResetGaugeVec{
		inner:  NewGaugeVec(opts, labelNames),
		labels: make(map[string][]string),
	}
}

// ResetGaugeVec is a GaugeVec that can be reset which deletes all previously set labels.
// This is useful to clear out labels that are no longer present.
type ResetGaugeVec struct {
	inner *prometheus.GaugeVec

	mu     sync.Mutex
	labels map[string][]string
}

func (g *ResetGaugeVec) WithLabelValues(lvs ...string) prometheus.Gauge {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.labels[labelsKey(lvs)] = lvs

	return g.inner.WithLabelValues(lvs...)
}

// Reset deletes all previously set label combinations whose leading label values equal lvs.
// An empty lvs deletes all previously set label combinations.
func (g *ResetGaugeVec) Reset(lvs ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for key, labels := range g.labels {
		if len(lvs) > len(labels) || !slices.Equal(labels[:len(lvs)], lvs) {
			continue
		}

		g.inner.DeleteLabelValues(labels...)
		delete(g.labels, key)
	}
}

// labelsKey returns an unambiguous map key for the label values,
// using length prefixes so values may contain any characters.
func labelsKey(lvs []string) string {
	var sb strings.Builder
	for _, lv := range lvs {
		_, _ = fmt.Fprintf(&sb, "%d:%s", len(lv), lv)
	}

	return sb.String()
}
