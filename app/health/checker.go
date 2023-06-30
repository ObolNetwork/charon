// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	scrapePeriod = 30 * time.Second
	maxScrapes   = 10
)

// NewChecker returns a new health checker.
func NewChecker(metadata Metadata, gatherer prometheus.Gatherer) *Checker {
	return &Checker{
		metadata:     metadata,
		checks:       checks,
		gatherer:     gatherer,
		scrapePeriod: scrapePeriod,
		maxScrapes:   maxScrapes,
		logFilter:    log.Filter(),
	}
}

// Checker is a health checker.
type Checker struct {
	metadata     Metadata
	checks       []check
	metrics      [][]*pb.MetricFamily
	gatherer     prometheus.Gatherer
	scrapePeriod time.Duration
	maxScrapes   int
	logFilter    z.Field
}

// Run runs the health checker until the context is canceled.
func (c *Checker) Run(ctx context.Context) {
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

// Instrument runs all health checks and updates the check gauge.
func (c *Checker) instrument(ctx context.Context) {
	for _, check := range c.checks {
		failing, err := check.Func(c.query, c.metadata)
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

	c.metrics = append(c.metrics, metrics)

	if len(c.metrics) > c.maxScrapes {
		c.metrics = c.metrics[1:]
	}

	return nil
}

// query return a selected time series for a provided metric name.
func (c *Checker) query(name string, selector labelSelector) ([]*pb.Metric, error) {
	var resp []*pb.Metric
	for _, fams := range c.metrics {
		for _, fam := range fams {
			if fam.GetName() != name {
				continue
			} else if len(fam.Metric) == 0 {
				continue
			}
			selected, err := selector(fam)
			if err != nil {
				return nil, errors.Wrap(err, "select metric")
			} else if selected == nil {
				continue
			}

			resp = append(resp, selected)

			break
		}
	}

	return resp, nil
}
