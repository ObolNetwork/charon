// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"regexp"

	pb "github.com/prometheus/client_model/go"

	"github.com/obolnetwork/charon/app/errors"
)

type labelSelector func(*pb.MetricFamily) (*pb.Metric, error)

// maxLabel returns the metric with the highest value.
func maxLabel(metricsFam *pb.MetricFamily) *pb.Metric { //nolint: unused // This is used in the future.
	var (
		max  float64
		resp *pb.Metric
	)
	for _, metric := range metricsFam.Metric {
		var val float64
		switch metricsFam.GetType() {
		case pb.MetricType_COUNTER:
			val = metric.Counter.GetValue()
		case pb.MetricType_GAUGE:
			val = metric.Gauge.GetValue()
		default:
			panic("invalid metric type for simple value labelSelector")
		}

		if max == 0 || val > max {
			max = val
			resp = metric
		}
	}

	return resp
}

// countNonZeroLabels counts the number of metrics that have a non-zero value.
func countNonZeroLabels(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	gauge := &pb.Metric{
		Gauge:       new(pb.Gauge),
		TimestampMs: metricsFam.Metric[0].TimestampMs,
	}

	for _, metric := range metricsFam.Metric {
		if metric.Gauge.GetValue() != 0 || metric.Counter.GetValue() != 0 {
			incremented := gauge.Gauge.GetValue() + 1
			gauge.Gauge.Value = &incremented
		}
	}

	return gauge, nil
}

// noLabels return the only metric in the family, or an error if there is not exactly one metric.
func noLabels(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	if len(metricsFam.Metric) != 1 {
		return nil, errors.New("expected exactly one metric")
	}

	return metricsFam.Metric[0], nil
}

// sumLabels returns a selector that sums the values of all metrics that match all of the label pairs.
func sumLabels(metricsFam *pb.MetricFamily) (*pb.Metric, error) { //nolint: unused // This is used in the future.
	sum := &pb.Metric{
		TimestampMs: metricsFam.Metric[0].TimestampMs,
	}
	for i, metric := range metricsFam.Metric {
		switch metricsFam.GetType() {
		case pb.MetricType_COUNTER:
			if i == 0 {
				sum.Counter = new(pb.Counter)
			}
			*sum.Counter.Value += metric.Counter.GetValue()
		case pb.MetricType_GAUGE:
			if i == 0 {
				sum.Gauge = new(pb.Gauge)
			}
			*sum.Gauge.Value += metric.Gauge.GetValue()
		case pb.MetricType_HISTOGRAM:
			return nil, errors.New("histogram sum not implemented yet")
		default:
			return nil, errors.New("invalid metric type")
		}
	}

	return sum, nil
}

// countLabels returns a selector that counts the number of metrics that match all of the label pairs.
func countLabels(labels ...*pb.LabelPair) func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	return func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
		count := &pb.Metric{
			Gauge:       new(pb.Gauge),
			TimestampMs: metricsFam.Metric[0].TimestampMs,
		}
		for _, metric := range metricsFam.Metric {
			if labelsContain(metric.Label, labels) {
				value := metric.Gauge.GetValue() + metric.Counter.GetValue()
				sum := count.Gauge.GetValue() + value
				count.Gauge.Value = &sum
			}
		}

		return count, nil
	}
}

// selectLabel returns a selector that returns the first metric that matches all of the label pairs.
func selectLabel(labels ...*pb.LabelPair) func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	return func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
		var found *pb.Metric
		for _, metric := range metricsFam.Metric {
			if labelsContain(metric.Label, labels) {
				if found != nil {
					return nil, errors.New("multiple metrics matching label selector")
				}
				found = metric
			}
		}

		return found, nil
	}
}

// labelsContain returns true if all of the label pairs in contain are found in labels.
func labelsContain(labels, contain []*pb.LabelPair) bool {
	for _, c := range contain {
		found := false
		for _, l := range labels {
			if l.GetName() != c.GetName() {
				continue
			}
			valueMatch, _ := regexp.MatchString(c.GetValue(), l.GetValue())
			if valueMatch {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
