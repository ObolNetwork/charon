// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	pb "github.com/prometheus/client_model/go"

	"github.com/obolnetwork/charon/app/errors"
)

// seriesReducer is a function that reduces a time series of metrics to a single value.
type seriesReducer func([]*pb.Metric) (float64, error)

// counterIncrease returns the increase in a time series of counter metrics.
func counterIncrease(samples []*pb.Metric) (float64, error) {
	if len(samples) < 2 {
		return 0, nil
	}

	first := samples[0].Counter
	last := samples[len(samples)-1].Counter

	if first == nil || last == nil {
		return 0, errors.New("bug: non-counter metrics passed")
	}

	return last.GetValue() - first.GetValue(), nil
}

// gaugeMax returns the maximum value in a time series of gauge metrics.
func gaugeMax(samples []*pb.Metric) (float64, error) {
	var max float64
	for _, sample := range samples {
		if sample.Gauge == nil {
			return 0, errors.New("bug: non-gauge metric passed")
		}

		if sample.Gauge.GetValue() > max {
			max = sample.Gauge.GetValue()
		}
	}

	return max, nil
}

// gaugeMin returns the minimum value in a time series of gauge metrics.
func gaugeMin(samples []*pb.Metric) (float64, error) {
	var min float64
	for _, sample := range samples {
		if sample.Gauge == nil {
			return 0, errors.New("bug: non-gauge metric passed")
		}

		if sample.Gauge.GetValue() < min {
			min = sample.Gauge.GetValue()
		}
	}

	return min, nil
}
