// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"testing"
	"time"

	pb "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var startTime = time.Now().Truncate(time.Hour)

func TestErrorLogsCheck(t *testing.T) {
	m := Metadata{}
	checkName := "error_logs"
	metricName := "app_log_error_total"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single zero", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(nil, 0)),
		)
	})

	t.Run("multiple constants", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(nil, 1, 1, 1)),
		)
	})

	t.Run("single error", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genCounter(nil, 0, 0, 1)),
		)
	})

	t.Run("multiple errors", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genCounter(nil, 10, 20, 30, 40, 50)),
		)
	})
}

func TestWarnLogsCheck(t *testing.T) {
	m := Metadata{
		NumValidators: 10,
	}
	checkName := "high_warning_log_rate"
	metricName := "app_log_warning_total"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single zero", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(nil, 0)),
		)
	})

	t.Run("multiple constants", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(nil, 1, 1, 1)),
		)
	})

	t.Run("too few", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(nil, 0, 0, 10)),
		)
	})

	t.Run("sufficient", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genCounter(nil, 10, 20, 30, 40, 500)),
		)
	})
}

func testCheck(t *testing.T, m Metadata, checkName string, expect bool, metrics []*pb.MetricFamily) {
	t.Helper()

	randomFamFoo := genFam("foo",
		genCounter(genLabels("foo", "foo1"), 1, 2, 3),
		genCounter(genLabels("foo", "foo2"), 1, 4, 8),
	)
	randomFamBar := genFam("bar",
		genGauge(genLabels("bar", "bar1"), 1, 1, 4),
		genGauge(genLabels("bar", "bar2"), 1, 1, 1),
	)

	var max int
	if len(metrics) > max {
		max = len(metrics)
	}
	if len(randomFamFoo) > max {
		max = len(randomFamFoo)
	}
	if len(randomFamBar) > max {
		max = len(randomFamBar)
	}

	multiFams := make([][]*pb.MetricFamily, max)
	for i := 0; i < max; i++ {
		var fam []*pb.MetricFamily
		if i < len(metrics) {
			fam = append(fam, metrics[i])
		}
		if i < len(randomFamFoo) {
			fam = append(fam, randomFamFoo[i])
		}
		if i < len(randomFamBar) {
			fam = append(fam, randomFamBar[i])
		}

		multiFams[i] = fam
	}

	for _, check := range checks {
		if check.Name != checkName {
			continue
		}

		failed, err := check.Func(newQueryFunc(multiFams), m)
		require.NoError(t, err)
		require.Equal(t, expect, failed)

		return
	}

	require.Fail(t, "check not found")
}

func genFam(name string, metrics ...[]*pb.Metric) []*pb.MetricFamily {
	typ := pb.MetricType_COUNTER
	if metrics[0][0].Gauge != nil {
		typ = pb.MetricType_GAUGE
	}

	var max int
	for _, series := range metrics {
		if len(series) > max {
			max = len(series)
		}
	}

	resp := make([]*pb.MetricFamily, max)
	for _, series := range metrics {
		for i, metric := range series {
			if resp[i] == nil {
				resp[i] = &pb.MetricFamily{
					Name:   &name,
					Type:   &typ,
					Metric: []*pb.Metric{},
				}
			}
			resp[i].Metric = append(resp[i].Metric, metric)
		}
	}

	return resp
}

func genLabels(nameVals ...string) []*pb.LabelPair {
	if len(nameVals)%2 != 0 {
		panic("must have even number of name/value pairs")
	}

	var resp []*pb.LabelPair
	for i := 0; i < len(nameVals); i += 2 {
		resp = append(resp, &pb.LabelPair{
			Name:  &nameVals[i],
			Value: &nameVals[i+1],
		})
	}

	return resp
}

func genCounter(labels []*pb.LabelPair, values ...int) []*pb.Metric {
	var resp []*pb.Metric
	for i, value := range values {
		ts := startTime.Add(time.Duration(i) * time.Second).UnixMilli()
		val := float64(value)
		resp = append(resp, &pb.Metric{
			Label: labels,
			Counter: &pb.Counter{
				Value: &val,
			},
			TimestampMs: &ts,
		})
	}

	return resp
}

func genGauge(labels []*pb.LabelPair, values ...int) []*pb.Metric {
	var resp []*pb.Metric
	for i, value := range values {
		ts := startTime.Add(time.Duration(i) * time.Second).UnixMilli()
		val := float64(value)
		resp = append(resp, &pb.Metric{
			Label: labels,
			Gauge: &pb.Gauge{
				Value: &val,
			},
			TimestampMs: &ts,
		})
	}

	return resp
}
