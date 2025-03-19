// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
		maxVal float64
		resp   *pb.Metric
	)
	for _, metric := range metricsFam.GetMetric() {
		var val float64
		switch metricsFam.GetType() {
		case pb.MetricType_COUNTER:
			val = metric.GetCounter().GetValue()
		case pb.MetricType_GAUGE:
			val = metric.GetGauge().GetValue()
		default:
			panic("invalid metric type for simple value labelSelector")
		}

		if maxVal == 0 || val > maxVal {
			maxVal = val
			resp = metric
		}
	}

	return resp
}

// countNonZeroLabels counts the number of metrics that have a non-zero value.
func countNonZeroLabels(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	timestamp := metricsFam.GetMetric()[0].GetTimestampMs()
	gauge := &pb.Metric{
		Gauge:       new(pb.Gauge),
		TimestampMs: &timestamp,
	}

	for _, metric := range metricsFam.GetMetric() {
		if metric.GetGauge().GetValue() != 0 || metric.GetCounter().GetValue() != 0 {
			incremented := gauge.GetGauge().GetValue() + 1
			gauge.Gauge.Value = &incremented
		}
	}

	return gauge, nil
}

// noLabels return the only metric in the family, or an error if there is not exactly one metric.
func noLabels(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	if len(metricsFam.GetMetric()) != 1 {
		return nil, errors.New("expected exactly one metric")
	}

	return metricsFam.GetMetric()[0], nil
}

// countLabels returns a selector that counts the number of metrics that match all of the label pairs.
func countLabels(labels ...*pb.LabelPair) func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	return func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
		timestamp := metricsFam.GetMetric()[0].GetTimestampMs()
		count := &pb.Metric{
			Gauge:       new(pb.Gauge),
			TimestampMs: &timestamp,
		}
		for _, metric := range metricsFam.GetMetric() {
			if labelsContain(metric.GetLabel(), labels) {
				value := metric.GetGauge().GetValue() + metric.GetCounter().GetValue()
				sum := count.GetGauge().GetValue() + value
				count.Gauge.Value = &sum
			}
		}

		return count, nil
	}
}

// sumLabels returns a selector that sums all metrics that match all of the label pairs.
func sumLabels(labels ...*pb.LabelPair) func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
	return func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
		if metricsFam.GetType() != pb.MetricType_GAUGE && metricsFam.GetType() != pb.MetricType_COUNTER {
			return nil, errors.New("bug: unsupported metric type")
		}

		timestamp := metricsFam.GetMetric()[0].GetTimestampMs()
		sum := &pb.Metric{
			Gauge:       new(pb.Gauge),
			TimestampMs: &timestamp,
		}
		for _, metric := range metricsFam.GetMetric() {
			if labelsContain(metric.GetLabel(), labels) {
				value := metric.GetGauge().GetValue() + metric.GetCounter().GetValue()
				summed := sum.GetGauge().GetValue() + value
				sum.Gauge.Value = &summed
			}
		}

		return sum, nil
	}
}

// selectLabel returns a selector that returns the first metric that matches all of the label pairs.
func selectLabel(labels ...*pb.LabelPair) func(metricsFam *pb.MetricFamily) (*pb.Metric, error) { //nolint: unused // This is used in the future.
	return func(metricsFam *pb.MetricFamily) (*pb.Metric, error) {
		var found *pb.Metric
		for _, metric := range metricsFam.GetMetric() {
			if labelsContain(metric.GetLabel(), labels) {
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
