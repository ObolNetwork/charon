// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package health provides health checks for the application.
package health

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pb "github.com/prometheus/client_model/go"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// scrapePeriod is the period between scrapes.
	scrapePeriod = 30 * time.Second
	// maxScrapes is the maximum number of scrapes to keep.
	maxScrapes = 10
	// labelsCardinalityThreshold is the threshold for single validator;
	// for N validators, the threshold is N * labelsCardinalityThreshold.
	labelsCardinalityThreshold = 100
)

// NewChecker returns a new health checker.
func NewChecker(metadata Metadata, gatherer prometheus.Gatherer, numValidators int) *Checker {
	return &Checker{
		metadata:      metadata,
		checks:        checks,
		gatherer:      gatherer,
		scrapePeriod:  scrapePeriod,
		maxScrapes:    maxScrapes,
		logFilter:     log.Filter(),
		numValidators: numValidators,
	}
}

// Checker is a health checker.
type Checker struct {
	metadata      Metadata
	checks        []check
	metrics       [][]*pb.MetricFamily
	gatherer      prometheus.Gatherer
	scrapePeriod  time.Duration
	maxScrapes    int
	logFilter     z.Field
	numValidators int
}

// Run runs the health checker until the context is canceled.
func (c *Checker) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "health")
	ticker := time.NewTicker(c.scrapePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.scrape(); err != nil {
				log.Warn(ctx, "Failed to scrape metrics", err)
				continue
			}

			c.instrument(ctx)
		}
	}
}

// instrument runs all health checks and updates the check gauge.
func (c *Checker) instrument(ctx context.Context) {
	for _, check := range c.checks {
		failing, err := check.Func(newQueryFunc(c.metrics), c.metadata)
		if err != nil {
			log.Warn(ctx, "Health check failed", err, z.Str("check", check.Name), c.logFilter)
			// Clear checks that fail
		}

		var val float64
		if failing {
			val = 1
		}

		checkGauge.WithLabelValues(string(check.Severity), check.Name).Set(val)
	}
}

// scrape scrapes metrics from the gatherer.
func (c *Checker) scrape() error {
	metrics, err := c.gatherer.Gather()
	if err != nil {
		return errors.Wrap(err, "gather metrics")
	}

	// Checking metrics with high cardinality.
	var gatherAgain bool
	for _, fams := range metrics {
		if fams.GetName() == "app_health_metrics_high_cardinality" {
			continue
		}

		var maxLabelsCount int
		for _, fam := range fams.GetMetric() {
			labelsCount := len(fam.GetLabel())
			if labelsCount > maxLabelsCount {
				maxLabelsCount = labelsCount
			}
		}
		if maxLabelsCount > labelsCardinalityThreshold*c.numValidators {
			highCardinalityGauge.WithLabelValues(fams.GetName()).Set(float64(maxLabelsCount))
			gatherAgain = true
		}
	}

	if gatherAgain {
		metrics, err = c.gatherer.Gather()
		if err != nil {
			return errors.Wrap(err, "gather metrics")
		}
	}

	c.metrics = append(c.metrics, metrics)

	if len(c.metrics) > c.maxScrapes {
		c.metrics = c.metrics[1:]
	}

	return nil
}

// newQueryFunc return a query function that returns the reduces value from selected time series for a provided metric name.
func newQueryFunc(metrics [][]*pb.MetricFamily) func(string, labelSelector, seriesReducer) (float64, error) {
	return func(name string, selector labelSelector, reducer seriesReducer) (float64, error) {
		var selectedMetrics []*pb.Metric
		for _, fams := range metrics {
			for _, fam := range fams {
				if fam.GetName() != name {
					continue
				} else if len(fam.GetMetric()) == 0 {
					continue
				}
				selected, err := selector(fam)
				if err != nil {
					return 0, errors.Wrap(err, "label selector")
				} else if selected == nil {
					continue
				}

				selectedMetrics = append(selectedMetrics, selected)

				break
			}
		}

		reducedVal, err := reducer(selectedMetrics)
		if err != nil {
			return 0, errors.Wrap(err, "series reducer")
		}

		return reducedVal, nil
	}
}
