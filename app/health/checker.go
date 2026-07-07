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
	// maxScrapes is the maximum number of scrapes to keep (5 minutes at 30s intervals).
	maxScrapes = 10
	// maxLongScrapes is the number of scrapes kept in the long-window buffer used by MetricsFunc
	// checks that compute rates over a longer history, e.g. SSE head delay and sync message
	// disagreement (1 hour at 30s intervals).
	maxLongScrapes = 120
	// seriesCardinalityThreshold is the maximum number of time series per metric family
	// for a single validator; for N validators, the threshold is N * seriesCardinalityThreshold.
	seriesCardinalityThreshold = 100

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
		maxLongScrapes:     maxLongScrapes,
		logFilter:          log.Filter(),
		numValidators:      numValidators,
		memorySamplePeriod: memorySamplePeriod,
		maxMemorySamples:   maxMemorySamples,
	}
}

// Checker is a health checker.
type Checker struct {
	metadata Metadata
	checks   []check
	// metrics is the short-window scrape buffer (maxScrapes) used by query-based Func checks.
	metrics [][]*pb.MetricFamily
	// longMetrics is the long-window scrape buffer (maxLongScrapes) passed to all MetricsFunc checks.
	longMetrics        [][]*pb.MetricFamily
	gatherer           prometheus.Gatherer
	scrapePeriod       time.Duration
	maxScrapes         int
	maxLongScrapes     int
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

		switch {
		case check.MemFunc != nil:
			failing, err = check.MemFunc(c.memorySnapshots, c.metadata)
		case check.MetricsFunc != nil:
			failing, err = check.MetricsFunc(c.longMetrics, c.metadata)
		default:
			failing, err = check.Func(newQueryFunc(c.metrics), c.metadata)
		}

		if err != nil {
			log.Warn(ctx, "Health check failed", err, z.Str("check", check.Name), c.logFilter)
			// Clear checks that fail
		}

		var val float64
		if failing {
			val = 1

			checkFailedCounter.WithLabelValues(string(check.Severity), check.Name, check.Description).Inc()
		}

		checkGauge.WithLabelValues(string(check.Severity), check.Name, check.Description).Set(val)
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

		seriesCount := len(fams.GetMetric())
		if seriesCount > seriesCardinalityThreshold*max(c.numValidators, 1) {
			highCardinalityGauge.WithLabelValues(fams.GetName()).Set(float64(seriesCount))

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

	c.longMetrics = append(c.longMetrics, metrics)
	if len(c.longMetrics) > c.maxLongScrapes {
		c.longMetrics = c.longMetrics[1:]
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

// sseHeadDelayCheck returns true if any beacon node delivered more than 4% of blocks with an SSE
// head delay above 4s during the current scrape window.
// It computes the increase in the le=4 and le=+Inf cumulative buckets across the scrape window
// (first vs last scrape), mirroring the rate-based Grafana panel query.
func sseHeadDelayCheck(scrapes [][]*pb.MetricFamily, _ Metadata) (bool, error) {
	const (
		metricName = "app_beacon_node_sse_head_delay"
		addrLabel  = "addr"
		threshold  = 0.04
	)

	if len(scrapes) < 2 {
		return false, nil
	}

	type bucketCounts struct {
		le4   float64
		leInf float64
	}

	getBuckets := func(fams []*pb.MetricFamily) map[string]bucketCounts {
		result := make(map[string]bucketCounts)

		for _, fam := range fams {
			if fam.GetName() != metricName {
				continue
			}

			for _, metric := range fam.GetMetric() {
				var addr string

				for _, lbl := range metric.GetLabel() {
					if lbl.GetName() == addrLabel {
						addr = lbl.GetValue()
						break
					}
				}

				h := metric.GetHistogram()

				var le4 float64

				for _, b := range h.GetBucket() {
					if b.GetUpperBound() == 4.0 {
						le4 = float64(b.GetCumulativeCount())
						break
					}
				}

				result[addr] = bucketCounts{
					le4:   le4,
					leInf: float64(h.GetSampleCount()),
				}
			}
		}

		return result
	}

	first := getBuckets(scrapes[0])
	last := getBuckets(scrapes[len(scrapes)-1])

	for addr, lastCounts := range last {
		firstCounts := first[addr]
		deltaInf := lastCounts.leInf - firstCounts.leInf

		if deltaInf == 0 {
			continue
		}

		deltaLe4 := lastCounts.le4 - firstCounts.le4
		fraction := 1.0 - deltaLe4/deltaInf

		if fraction > threshold {
			return true, nil
		}
	}

	return false, nil
}

// syncMsgDisagreementCheck returns true if any peer signed a different sync committee head block
// root than the largest cohort for more than syncMsgDisagreementThreshold of the sync messages it
// submitted during the scrape window. It computes the per-peer increase of the cohort rank counter
// (rank!="0" = disagreed, all ranks = total) across the window, mirroring the Grafana panel.
func syncMsgDisagreementCheck(scrapes [][]*pb.MetricFamily, _ Metadata) (bool, error) {
	const (
		metricName = "core_tracker_parsig_cohort_rank_total"
		peerLabel  = "peer_idx"
		rankLabel  = "rank"
		threshold  = 0.05
		// minSamples guards against noisy ratios for peers that barely participated in the window.
		// MetricsFunc checks run over the ~1-hour SSE scrape buffer (~300 sync slots), so 20 is a
		// low participation floor that mainly rejects startup and mostly-offline peers.
		minSamples = 20
	)

	if len(scrapes) < 2 {
		return false, nil
	}

	type counts struct{ total, disagreed float64 }

	collect := func(fams []*pb.MetricFamily) map[string]counts {
		result := make(map[string]counts)

		for _, fam := range fams {
			if fam.GetName() != metricName {
				continue
			}

			for _, metric := range fam.GetMetric() {
				var peerIdx, rank string

				for _, lbl := range metric.GetLabel() {
					switch lbl.GetName() {
					case peerLabel:
						peerIdx = lbl.GetValue()
					case rankLabel:
						rank = lbl.GetValue()
					default:
					}
				}

				c := result[peerIdx]

				c.total += metric.GetCounter().GetValue()
				if rank != "0" {
					c.disagreed += metric.GetCounter().GetValue()
				}

				result[peerIdx] = c
			}
		}

		return result
	}

	first := collect(scrapes[0])
	last := collect(scrapes[len(scrapes)-1])

	for peerIdx, lastCounts := range last {
		deltaTotal := lastCounts.total - first[peerIdx].total
		if deltaTotal < minSamples {
			continue
		}

		deltaDisagreed := lastCounts.disagreed - first[peerIdx].disagreed
		if deltaDisagreed/deltaTotal > threshold {
			return true, nil
		}
	}

	return false, nil
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
