// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	pb "github.com/prometheus/client_model/go"

	"github.com/obolnetwork/charon/app/errors"
)

// seriesReducer is a function that reduces a time series of metrics to a single value.
type seriesReducer func([]*pb.Metric) (float64, error)

// increase returns the increase in a time series of counter metrics.
func increase(samples []*pb.Metric) (float64, error) {
	if len(samples) < 2 {
		return 0, nil
	}

	if samples[0].GetCounter() == nil && samples[0].GetGauge() == nil {
		return 0, errors.New("bug: unsupported metric passed")
	}

	first := samples[0].GetCounter().GetValue() + samples[0].GetGauge().GetValue()
	last := samples[len(samples)-1].GetCounter().GetValue() + samples[len(samples)-1].GetGauge().GetValue()

	return last - first, nil
}

// gaugeMax returns the maximum value in a time series of gauge metrics.
func gaugeMax(samples []*pb.Metric) (float64, error) {
	var maxVal float64
	for _, sample := range samples {
		if sample.GetGauge() == nil {
			return 0, errors.New("bug: non-gauge metric passed")
		}

		if sample.GetGauge().GetValue() > maxVal {
			maxVal = sample.GetGauge().GetValue()
		}
	}

	return maxVal, nil
}
