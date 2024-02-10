// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"testing"
	"time"

	pb "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var startTime = time.Now().Truncate(time.Hour)

func TestProposalFailuresCheck(t *testing.T) {
	m := Metadata{
		QuorumPeers: 2,
	}
	checkName := "proposal_failures"
	metricName := "core_tracker_failed_duties_total"

	proposalFull := genLabels("duty", "proposal")
	proposalBlind := genLabels("duty", "builder_proposal")
	attestation := genLabels("duty", "attester")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("no failures", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(proposalFull, 1, 1, 1, 1),
				genCounter(proposalBlind, 0, 0, 0, 0),
				genCounter(attestation, 2, 2, 2, 2),
			),
		)
	})

	t.Run("full proposal failures", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(proposalFull, 0, 0, 1, 1),
				genCounter(proposalBlind, 0, 0, 0, 0),
				genCounter(attestation, 0, 0, 0, 0),
			),
		)
	})

	t.Run("blind proposal failures", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(proposalFull, 0, 0, 0, 0),
				genCounter(proposalBlind, 0, 0, 1, 1),
				genCounter(attestation, 0, 0, 0, 0),
			),
		)
	})

	t.Run("attestation failures", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(proposalFull, 0, 0, 0, 0),
				genCounter(proposalBlind, 0, 0, 0, 0),
				genCounter(attestation, 0, 0, 1, 1),
			),
		)
	})

	t.Run("multiple failures", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(proposalFull, 0, 0, 1, 1),
				genCounter(proposalBlind, 0, 0, 1, 1),
				genCounter(attestation, 0, 0, 1, 1),
			),
		)
	})
}

func TestPendingValidatorsCheck(t *testing.T) {
	m := Metadata{
		QuorumPeers: 2,
	}
	checkName := "pending_validators"
	metricName := "core_scheduler_validator_status"

	val1Pending := genLabels("pubkey", "1", "status", "pending")
	val1Active := genLabels("pubkey", "1", "status", "active")
	val2Active := genLabels("pubkey", "2", "status", "active")
	val3Pending := genLabels("pubkey", "3", "status", "pending")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single active", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(val1Active, 1, 1, 1, 1),
			),
		)
	})

	t.Run("single pending", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(val1Pending, 1, 1, 1, 1),
			),
		)
	})

	t.Run("single activated", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(val1Pending, 1, 1, 0, 0),
				genGauge(val1Active, 0, 0, 1, 1),
			),
		)
	})

	t.Run("1o3 pending", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(val1Pending, 0, 0, 0, 0),
				genGauge(val1Active, 1, 1, 1, 1),
				genGauge(val2Active, 1, 1, 1, 1),
				genGauge(val3Pending, 1, 1, 1, 1),
			),
		)
	})
}

func TestInsufficientPeerCheck(t *testing.T) {
	m := Metadata{
		QuorumPeers: 2,
	}
	checkName := "insufficient_connected_peers"
	metricName := "p2p_ping_success"

	peer1 := genLabels("peer", "1")
	peer2 := genLabels("peer", "2")
	peer3 := genLabels("peer", "3")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, true, nil)
	})

	t.Run("no peers", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(peer1, 0, 0, 0, 0),
				genGauge(peer2, 0, 0, 0, 0),
				genGauge(peer3, 0, 0, 0, 0),
			),
		)
	})

	t.Run("all peers", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(peer1, 1, 1, 1),
				genGauge(peer2, 1, 1, 1),
				genGauge(peer3, 1, 1, 1),
			),
		)
	})

	t.Run("quorum peers", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(peer1, 0, 0, 0),
				genGauge(peer2, 1, 1, 1),
				genGauge(peer3, 1, 1, 1),
			),
		)
	})

	t.Run("blip", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(peer1, 1, 0, 1),
				genGauge(peer2, 1, 0, 1),
				genGauge(peer3, 1, 0, 1),
			),
		)
	})
}

func TestBNSyncingCheck(t *testing.T) {
	m := Metadata{}
	checkName := "beacon_node_syncing"
	metricName := "app_monitoring_beacon_node_syncing"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single zero", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(nil, 0)),
		)
	})

	t.Run("multiple constants", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(nil, 1, 1, 1)),
		)
	})

	t.Run("blip", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(nil, 0, 1, 0)),
		)
	})
}

func TestErrorLogsCheck(t *testing.T) {
	m := Metadata{
		NumValidators: 10,
	}
	checkName := "high_error_log_rate"
	metricName := "app_log_error_total"

	topicA := genLabels("topic", "a")
	topicB := genLabels("topic", "b")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single zero", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 0)),
		)
	})

	t.Run("multiple zeros", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(topicA, 0, 0, 0),
				genCounter(topicB, 0, 0, 0),
			),
		)
	})

	t.Run("multiple constants", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 1, 1, 1)),
		)
	})

	t.Run("too few", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 0, 0, 10)),
		)
	})

	t.Run("too few multi", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(topicA, 0, 0, 5),
				genCounter(topicB, 0, 0, 5),
			),
		)
	})

	t.Run("sufficient", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(topicA, 10, 20, 30, 40, 500)),
		)
	})
}

func TestWarnLogsCheck(t *testing.T) {
	m := Metadata{
		NumValidators: 10,
	}
	checkName := "high_warning_log_rate"
	metricName := "app_log_warning_total"
	topicA := genLabels("topic", "a")
	topicB := genLabels("topic", "b")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single zero", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 0)),
		)
	})

	t.Run("multiple zeros", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(topicA, 0, 0, 0),
				genCounter(topicB, 0, 0, 0),
			),
		)
	})

	t.Run("multiple constants", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 1, 1, 1)),
		)
	})

	t.Run("too few", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genCounter(topicA, 0, 0, 10)),
		)
	})

	t.Run("too few multi", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(topicA, 0, 0, 5),
				genCounter(topicB, 0, 0, 5),
			),
		)
	})

	t.Run("sufficient", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(topicA, 10, 20, 30, 40, 500)),
		)
	})
}

func TestHighRegistrationFailuresRateCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_registration_failures_rate"
	metricName := "core_bcast_recast_errors_total"
	pregenLabel := genLabels("source", "pregen")
	downsteamLabel := genLabels("source", "downstream")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("same errors count", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(pregenLabel, 1, 1, 1), // No increments
			),
		)
	})

	t.Run("incrementing errors count", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(downsteamLabel, 0, 1, 2, 10),
			),
		)
	})

	t.Run("both labels have stable errors count", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(pregenLabel, 1, 1, 1),
				genGauge(downsteamLabel, 1, 1, 1),
			),
		)
	})

	t.Run("both labels have increasing errors count", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(pregenLabel, 10, 15, 18),
				genGauge(downsteamLabel, 1, 2, 3),
			),
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
