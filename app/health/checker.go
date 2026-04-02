// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	// memorySamplePeriod is the period between memory snapshots.
	memorySamplePeriod = 30 * time.Minute
	// maxMemorySamples is the number of memory snapshots to keep (48h at 30-min intervals).
	maxMemorySamples = 96
	// memoryWarmupPeriod is the time after a restart during which memory samples are excluded.
	// Charon memory takes 1-4 hours to reach equilibrium after a restart.
	memoryWarmupPeriod = 4 * time.Hour
	// minValidMemorySamples is the minimum number of valid (non-warmup) samples required
	// in each 24h window before the memory leak check will fire.
	minValidMemorySamples = 8
	// memoryLeakThreshold is the fractional growth in average memory between the two 24h
	// windows that triggers the warning (0.05 = 5%).
	memoryLeakThreshold = 0.05
)

// memorySnapshot holds a single periodic memory observation.
type memorySnapshot struct {
	bytes      float64   // go_memstats_heap_inuse_bytes at capture time
	startSecs  float64   // app_start_time_secs at capture time, used to detect restarts
	capturedAt time.Time // wall-clock time of the snapshot
}

// NewChecker returns a new health checker.
func NewChecker(metadata Metadata, gatherer prometheus.Gatherer, numValidators int) *Checker {
	return &Checker{
		metadata:           metadata,
		checks:             checks,
		gatherer:           gatherer,
		scrapePeriod:       scrapePeriod,
		maxScrapes:         maxScrapes,
		logFilter:          log.Filter(),
		numValidators:      numValidators,
		memorySamplePeriod: memorySamplePeriod,
		maxMemorySamples:   maxMemorySamples,
	}
}

// Checker is a health checker.
type Checker struct {
	metadata           Metadata
	checks             []check
	metrics            [][]*pb.MetricFamily
	gatherer           prometheus.Gatherer
	scrapePeriod       time.Duration
	maxScrapes         int
	logFilter          z.Field
	numValidators      int
	memorySnapshots    []memorySnapshot
	memorySamplePeriod time.Duration
	maxMemorySamples   int
}

// Run runs the health checker until the context is canceled.
func (c *Checker) Run(ctx context.Context) {
	ctx = log.WithTopic(ctx, "health")

	ticker := time.NewTicker(c.scrapePeriod)
	defer ticker.Stop()

	memTicker := time.NewTicker(c.memorySamplePeriod)
	defer memTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-memTicker.C:
			c.sampleMemory()
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
		var (
			failing bool
			err     error
		)

		if check.MemFunc != nil {
			failing, err = check.MemFunc(c.memorySnapshots, c.metadata)
		} else {
			failing, err = check.Func(newQueryFunc(c.metrics), c.metadata)
		}

		if err != nil {
			log.Warn(ctx, "Health check failed", err, z.Str("check", check.Name), c.logFilter)
			// Clear checks that fail
		}

		var val float64
		if failing {
			val = 1

			checkFailedCounter.WithLabelValues(string(check.Severity), check.Name).Inc()
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

// sampleMemory records a periodic memory snapshot for use by the memory leak check.
func (c *Checker) sampleMemory() {
	metrics, err := c.gatherer.Gather()
	if err != nil {
		return // best effort
	}

	var memBytes, startSecs float64

	for _, fam := range metrics {
		switch fam.GetName() { //nolint:revive
		case "go_memstats_heap_inuse_bytes":
			if len(fam.GetMetric()) > 0 {
				memBytes = fam.GetMetric()[0].GetGauge().GetValue()
			}
		case "app_start_time_secs":
			if len(fam.GetMetric()) > 0 {
				startSecs = fam.GetMetric()[0].GetGauge().GetValue()
			}
		}
	}

	if memBytes == 0 {
		return // metric not available yet
	}

	c.memorySnapshots = append(c.memorySnapshots, memorySnapshot{
		bytes:      memBytes,
		startSecs:  startSecs,
		capturedAt: time.Now(),
	})

	if len(c.memorySnapshots) > c.maxMemorySamples {
		c.memorySnapshots = c.memorySnapshots[1:]
	}
}

// memoryLeakCheck returns true if average memory in the most recent 24h has grown by more than
// memoryLeakThreshold compared to the previous 24h, ignoring samples taken within
// memoryWarmupPeriod of a restart.
func memoryLeakCheck(snapshots []memorySnapshot, _ Metadata) (bool, error) {
	if len(snapshots) < maxMemorySamples {
		return false, nil // not enough history yet
	}

	half := len(snapshots) / 2

	avgOlder, ok := avgValidMemory(snapshots[:half])
	if !ok {
		return false, nil // not enough valid samples in older window
	}

	avgRecent, ok := avgValidMemory(snapshots[half:])
	if !ok {
		return false, nil // not enough valid samples in recent window
	}

	return avgRecent > avgOlder*(1+memoryLeakThreshold), nil
}

// avgValidMemory computes the average memory bytes across snapshots, excluding any taken within
// memoryWarmupPeriod of the process start (post-restart cool-down). Returns false if fewer than
// minValidMemorySamples valid samples exist.
func avgValidMemory(snapshots []memorySnapshot) (float64, bool) {
	var (
		sum   float64
		count int
	)

	for _, s := range snapshots {
		restartTime := time.Unix(int64(s.startSecs), 0)
		if s.capturedAt.Sub(restartTime) < memoryWarmupPeriod {
			continue // process still warming up after restart
		}

		sum += s.bytes
		count++
	}

	if count < minValidMemorySamples {
		return 0, false
	}

	return sum / float64(count), true
}

// newQueryFunc return a query function that returns the reduces value from selected time series for a provided metric name.
func newQueryFunc(metrics [][]*pb.MetricFamily) func(string, labelSelector, seriesReducer) (float64, error) {
	return func(name string, selector labelSelector, reducer seriesReducer) (float64, error) {
		var selectedMetrics []*pb.Metric

		for _, fams := range metrics {
			for _, fam := range fams {
				if fam.GetName() != name || len(fam.GetMetric()) == 0 {
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
