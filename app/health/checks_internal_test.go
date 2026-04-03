// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package health

import (
	"testing"
	"time"

	pb "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var startTime = time.Now().Truncate(time.Hour)

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

func TestHighRegistrationFailuresRateCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_registration_failures_rate"
	metricName := "core_scheduler_submit_registration_errors_total"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("same errors count", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genCounter(genLabels(), 1, 1, 1), // No increments
			),
		)
	})

	t.Run("have increasing errors count", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genCounter(genLabels(), 10, 15, 18),
				genCounter(genLabels(), 1, 2, 3),
			),
		)
	})
}

func TestMetricsHighCardinalityCheck(t *testing.T) {
	m := Metadata{}
	checkName := "metrics_high_cardinality"
	metricName := "app_health_metrics_high_cardinality"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("high cardinality", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(genLabels("name", "metric1"), 1, 1, 1),
				genGauge(genLabels("name", "metric2"), 3, 5, 0),
			),
		)
	})
}

func TestUsingFallbackBeaconNodesCheck(t *testing.T) {
	m := Metadata{}
	checkName := "using_fallback_beacon_nodes"
	metricName := "app_eth2_using_fallback"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("no fallback", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGauge(nil, 0, 0, 0),
			),
		)
	})

	t.Run("single fallback", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(nil, 0, 1, 0),
			),
		)
	})
}

func TestHighBeaconNodeLatencyCheck(t *testing.T) {
	m := Metadata{}
	metricName := "app_eth2_latency_seconds"

	attestation := genLabels("endpoint", "attestation")
	proposal := genLabels("endpoint", "proposal")
	submitBlinded := genLabels("endpoint", "submit_blinded_proposal")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, "high_beacon_node_latency", false, nil)
		testCheck(t, m, "high_beacon_node_proposal_latency", false, nil)
	})

	t.Run("all low latency", func(t *testing.T) {
		fam := genHistFam(metricName,
			genHistogram(attestation, 0.5, 1, 0.5, 1, 0.5, 1),
			genHistogram(proposal, 0.8, 1, 0.8, 1, 0.8, 1),
			genHistogram(submitBlinded, 0.9, 1, 0.9, 1, 0.9, 1),
		)
		testCheck(t, m, "high_beacon_node_latency", false, fam)
		testCheck(t, m, "high_beacon_node_proposal_latency", false, fam)
	})

	t.Run("regular endpoint above 1s", func(t *testing.T) {
		fam := genHistFam(metricName,
			genHistogram(attestation, 1.5, 1, 1.5, 1, 1.5, 1),
			genHistogram(proposal, 0.5, 1, 0.5, 1, 0.5, 1),
		)
		testCheck(t, m, "high_beacon_node_latency", true, fam)
		testCheck(t, m, "high_beacon_node_proposal_latency", false, fam)
	})

	t.Run("proposal above 1s but below 2s does not trigger general check", func(t *testing.T) {
		fam := genHistFam(metricName,
			genHistogram(attestation, 0.5, 1, 0.5, 1, 0.5, 1),
			genHistogram(proposal, 1.5, 1, 1.5, 1, 1.5, 1),
		)
		testCheck(t, m, "high_beacon_node_latency", false, fam)
		testCheck(t, m, "high_beacon_node_proposal_latency", false, fam)
	})

	t.Run("proposal above 2s", func(t *testing.T) {
		fam := genHistFam(metricName,
			genHistogram(attestation, 0.5, 1, 0.5, 1, 0.5, 1),
			genHistogram(proposal, 2.5, 1, 2.5, 1, 2.5, 1),
		)
		testCheck(t, m, "high_beacon_node_latency", false, fam)
		testCheck(t, m, "high_beacon_node_proposal_latency", true, fam)
	})

	t.Run("submit_blinded_proposal above 2s", func(t *testing.T) {
		fam := genHistFam(metricName,
			genHistogram(attestation, 0.5, 1, 0.5, 1, 0.5, 1),
			genHistogram(submitBlinded, 2.5, 1, 2.5, 1, 2.5, 1),
		)
		testCheck(t, m, "high_beacon_node_latency", false, fam)
		testCheck(t, m, "high_beacon_node_proposal_latency", true, fam)
	})
}

func TestHighPeerClockOffsetCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_peer_clock_offset"
	metricName := "app_peerinfo_clock_offset_seconds"

	peer1 := genLabels("peer", "1")
	peer2 := genLabels("peer", "2")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("low offset", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGaugef(peer1, 0.1, 0.1, 0.1),
				genGaugef(peer2, -0.05, -0.05, -0.05),
			),
		)
	})

	t.Run("high positive offset", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGaugef(peer1, 0.3, 0.3, 0.3),
				genGaugef(peer2, 0.1, 0.1, 0.1),
			),
		)
	})

	t.Run("high negative offset", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGaugef(peer1, -0.3, -0.3, -0.3),
				genGaugef(peer2, 0.1, 0.1, 0.1),
			),
		)
	})

	t.Run("exactly at threshold", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName,
				genGaugef(peer1, 0.2, 0.2, 0.2),
			),
		)
	})

	t.Run("just above threshold", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGaugef(peer1, 0.201, 0.201, 0.201),
			),
		)
	})
}

func TestHighPeerPingLatencyCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_peer_ping_latency"
	metricName := "p2p_ping_latency_secs"

	peer1 := genLabels("peer", "1")
	peer2 := genLabels("peer", "2")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("low latency", func(t *testing.T) {
		// avg = 0.05s (50ms) per peer
		testCheck(t, m, checkName, false,
			genHistFam(metricName,
				genHistogram(peer1, 0.05, 1, 0.05, 1, 0.05, 1),
				genHistogram(peer2, 0.04, 1, 0.04, 1, 0.04, 1),
			),
		)
	})

	t.Run("high latency single peer", func(t *testing.T) {
		// avg = 0.2s (200ms) for peer1
		testCheck(t, m, checkName, true,
			genHistFam(metricName,
				genHistogram(peer1, 0.2, 1, 0.2, 1, 0.2, 1),
				genHistogram(peer2, 0.05, 1, 0.05, 1, 0.05, 1),
			),
		)
	})

	t.Run("exactly at threshold", func(t *testing.T) {
		// avg = 0.15s (150ms) — not over the threshold
		testCheck(t, m, checkName, false,
			genHistFam(metricName,
				genHistogram(peer1, 0.15, 1, 0.15, 1, 0.15, 1),
			),
		)
	})

	t.Run("just above threshold", func(t *testing.T) {
		// avg = 0.151s (151ms)
		testCheck(t, m, checkName, true,
			genHistFam(metricName,
				genHistogram(peer1, 0.151, 1, 0.151, 1, 0.151, 1),
			),
		)
	})
}

func TestHighConsensusRoundsCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_consensus_rounds"
	metricName := "core_consensus_decided_rounds"

	proposerLabels := genLabels("duty", "proposer", "protocol", "qbft", "timer", "round_timeout")
	attesterLabels := genLabels("duty", "attester", "protocol", "qbft", "timer", "round_timeout")
	randaoLabels := genLabels("duty", "randao", "protocol", "qbft", "timer", "round_timeout")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("single round proposer", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(proposerLabels, 1, 1, 1)),
		)
	})

	t.Run("two rounds proposer", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(proposerLabels, 1, 1, 2)),
		)
	})

	t.Run("two rounds attester", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(attesterLabels, 1, 1, 2)),
		)
	})

	t.Run("high rounds other duty not triggered", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(randaoLabels, 5, 5, 5)),
		)
	})

	t.Run("high rounds other duty does not mask attester", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName,
				genGauge(randaoLabels, 5, 5, 5),
				genGauge(attesterLabels, 1, 1, 2),
			),
		)
	})
}

func TestLocalBlockProposalCheck(t *testing.T) {
	m := Metadata{}
	checkName := "local_block_proposal"
	metricName := "core_fetcher_proposal_blinded"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("blinded proposal (MEV)", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(nil, 1, 1, 1)),
		)
	})

	t.Run("local block proposal", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(nil, 2, 2, 2)),
		)
	})
}

func TestHighParsigdbStoreLatencyCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_parsigdb_store_latency"
	metricName := "core_parsigdb_store"

	attester0 := genLabels("duty", "attester", "peer_idx", "0")
	attester1 := genLabels("duty", "attester", "peer_idx", "1")
	proposer0 := genLabels("duty", "proposer", "peer_idx", "0")

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("low latency", func(t *testing.T) {
		// avg = 0.5s per peer — below the 2s threshold
		testCheck(t, m, checkName, false,
			genHistFam(metricName,
				genHistogram(attester0, 0.5, 1, 0.5, 1, 0.5, 1),
				genHistogram(attester1, 0.3, 1, 0.3, 1, 0.3, 1),
			),
		)
	})

	t.Run("high latency single peer triggers warning", func(t *testing.T) {
		// avg = 2.5s for peer 0 — above the 2s threshold
		testCheck(t, m, checkName, true,
			genHistFam(metricName,
				genHistogram(attester0, 2.5, 1, 2.5, 1, 2.5, 1),
				genHistogram(attester1, 0.3, 1, 0.3, 1, 0.3, 1),
			),
		)
	})

	t.Run("high latency for proposer duty does not trigger", func(t *testing.T) {
		// proposer duty is not included in the attester check
		testCheck(t, m, checkName, false,
			genHistFam(metricName,
				genHistogram(proposer0, 5.0, 1, 5.0, 1, 5.0, 1),
			),
		)
	})

	t.Run("exactly at threshold does not trigger", func(t *testing.T) {
		// avg = 2.0s — not strictly above the threshold
		testCheck(t, m, checkName, false,
			genHistFam(metricName,
				genHistogram(attester0, 2.0, 1, 2.0, 1, 2.0, 1),
			),
		)
	})

	t.Run("just above threshold triggers", func(t *testing.T) {
		// avg = 2.1s — above the 2s threshold
		testCheck(t, m, checkName, true,
			genHistFam(metricName,
				genHistogram(attester0, 2.1, 1, 2.1, 1, 2.1, 1),
			),
		)
	})
}

func TestHighGoroutineCountCheck(t *testing.T) {
	m := Metadata{}
	checkName := "high_goroutine_count"
	metricName := "go_goroutines"

	t.Run("no data", func(t *testing.T) {
		testCheck(t, m, checkName, false, nil)
	})

	t.Run("below threshold", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(nil, 500, 500, 500)),
		)
	})

	t.Run("exactly at threshold", func(t *testing.T) {
		testCheck(t, m, checkName, false,
			genFam(metricName, genGauge(nil, 1000, 1000, 1000)),
		)
	})

	t.Run("above threshold", func(t *testing.T) {
		testCheck(t, m, checkName, true,
			genFam(metricName, genGauge(nil, 500, 500, 1001)),
		)
	})
}

func TestHighBeaconNodeSSEHeadDelayCheck(t *testing.T) {
	// makeScrapes builds a two-scrape history for sseHeadDelayCheck.
	// For each addr, firstLe4/firstTotal are the cumulative counts in scrape[0],
	// and delta is the new blocks arriving between scrapes, with deltaLate above 4s.
	makeScrapes := func(addr string, firstLe4, firstTotal, deltaLe4, deltaTotal uint64) [][]*pb.MetricFamily {
		mkFam := func(le4, total uint64) []*pb.MetricFamily {
			name := "app_beacon_node_sse_head_delay"
			addrVal := addr
			typ := pb.MetricType_HISTOGRAM
			bound4 := 4.0
			count := total
			sum := 0.0

			return []*pb.MetricFamily{{
				Name: &name,
				Type: &typ,
				Metric: []*pb.Metric{{
					Label: []*pb.LabelPair{{Name: func() *string { s := "addr"; return &s }(), Value: &addrVal}}, //nolint:goconst
					Histogram: &pb.Histogram{
						SampleCount: &count,
						SampleSum:   &sum,
						Bucket: []*pb.Bucket{{
							UpperBound:      &bound4,
							CumulativeCount: &le4,
						}},
					},
				}},
			}}
		}

		return [][]*pb.MetricFamily{
			mkFam(firstLe4, firstTotal),
			mkFam(firstLe4+deltaLe4, firstTotal+deltaTotal),
		}
	}

	t.Run("no data", func(t *testing.T) {
		failing, err := sseHeadDelayCheck(nil, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("single scrape only", func(t *testing.T) {
		failing, err := sseHeadDelayCheck([][]*pb.MetricFamily{{}}, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("all blocks within 4s", func(t *testing.T) {
		// 100 new blocks, all within 4s → 0% late
		scrapes := makeScrapes("http://bn1:5052", 0, 0, 100, 100)
		failing, err := sseHeadDelayCheck(scrapes, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("below 4% does not trigger", func(t *testing.T) {
		// 100 new blocks, 3 late → 3% late
		scrapes := makeScrapes("http://bn1:5052", 0, 0, 97, 100)
		failing, err := sseHeadDelayCheck(scrapes, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("above 4% triggers warning", func(t *testing.T) {
		// 100 new blocks, 5 late → 5% late
		scrapes := makeScrapes("http://bn1:5052", 0, 0, 95, 100)
		failing, err := sseHeadDelayCheck(scrapes, Metadata{})
		require.NoError(t, err)
		require.True(t, failing)
	})

	t.Run("historical dilution does not mask recent spike", func(t *testing.T) {
		// 10000 prior blocks all good, then 100 new with 5 late → still 5% in window
		scrapes := makeScrapes("http://bn1:5052", 10000, 10000, 95, 100)
		failing, err := sseHeadDelayCheck(scrapes, Metadata{})
		require.NoError(t, err)
		require.True(t, failing)
	})

	t.Run("single bad beacon node triggers warning", func(t *testing.T) {
		// Build two-addr scrapes manually: bn1 5% late, bn2 1% late
		name := "app_beacon_node_sse_head_delay"
		typ := pb.MetricType_HISTOGRAM
		bound4 := 4.0

		mkMetric := func(addr string, le4, total uint64) *pb.Metric {
			addrVal := addr
			sum := 0.0

			return &pb.Metric{
				Label: []*pb.LabelPair{{Name: func() *string { s := "addr"; return &s }(), Value: &addrVal}},
				Histogram: &pb.Histogram{
					SampleCount: &total,
					SampleSum:   &sum,
					Bucket:      []*pb.Bucket{{UpperBound: &bound4, CumulativeCount: &le4}},
				},
			}
		}

		scrapes := [][]*pb.MetricFamily{
			{{Name: &name, Type: &typ, Metric: []*pb.Metric{mkMetric("http://bn1:5052", 0, 0), mkMetric("http://bn2:5052", 0, 0)}}},
			{{Name: &name, Type: &typ, Metric: []*pb.Metric{mkMetric("http://bn1:5052", 95, 100), mkMetric("http://bn2:5052", 99, 100)}}},
		}

		failing, err := sseHeadDelayCheck(scrapes, Metadata{})
		require.NoError(t, err)
		require.True(t, failing)
	})
}

func TestMemoryLeakCheck(t *testing.T) {
	now := time.Now()
	startSecs := float64(now.Add(-48 * time.Hour).Unix()) // started 48h ago, fully warmed up

	// makeSnapshots builds a slice of maxMemorySamples snapshots with the given bytes values.
	// The values slice is cycled if shorter than maxMemorySamples.
	makeSnapshots := func(values []float64) []memorySnapshot {
		snaps := make([]memorySnapshot, maxMemorySamples)
		for i := range maxMemorySamples {
			// Space snapshots memorySamplePeriod apart, oldest first.
			capturedAt := now.Add(-time.Duration(maxMemorySamples-1-i) * memorySamplePeriod)
			snaps[i] = memorySnapshot{
				bytes:      values[i%len(values)],
				startSecs:  startSecs,
				capturedAt: capturedAt,
			}
		}

		return snaps
	}

	t.Run("no data", func(t *testing.T) {
		failing, err := memoryLeakCheck(nil, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("partial data", func(t *testing.T) {
		snaps := makeSnapshots([]float64{100})[:50] // only 50 of 96
		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("stable memory", func(t *testing.T) {
		snaps := makeSnapshots([]float64{500})
		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("exactly 5% growth is not above threshold", func(t *testing.T) {
		snaps := makeSnapshots([]float64{100})
		// Set recent half to exactly 105 (5% more).
		for i := maxMemorySamples / 2; i < maxMemorySamples; i++ {
			snaps[i].bytes = 105
		}

		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.False(t, failing)
	})

	t.Run("above 5% growth triggers warning", func(t *testing.T) {
		snaps := makeSnapshots([]float64{100})
		// Set recent half to 106 (6% more).
		for i := maxMemorySamples / 2; i < maxMemorySamples; i++ {
			snaps[i].bytes = 106
		}

		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.True(t, failing)
	})

	t.Run("all recent samples in warmup", func(t *testing.T) {
		snaps := makeSnapshots([]float64{100})
		recentStart := float64(now.Add(-2 * time.Hour).Unix()) // restarted 2h ago
		// Mark all recent-window snapshots as post-restart warmup.
		for i := maxMemorySamples / 2; i < maxMemorySamples; i++ {
			snaps[i].startSecs = recentStart
		}

		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.False(t, failing) // not enough valid samples in recent window
	})

	t.Run("restart in older window does not prevent check", func(t *testing.T) {
		snaps := makeSnapshots([]float64{100})
		olderStart := float64(now.Add(-46 * time.Hour).Unix()) // restarted 46h ago
		// Mark first few older samples as warmup — but enough remain valid.
		for i := range 4 {
			snaps[i].startSecs = olderStart
		}
		// Memory grew 20% in the recent window.
		for i := maxMemorySamples / 2; i < maxMemorySamples; i++ {
			snaps[i].bytes = 120
		}

		failing, err := memoryLeakCheck(snaps, Metadata{})
		require.NoError(t, err)
		require.True(t, failing)
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

	var maxVal int
	if len(metrics) > maxVal {
		maxVal = len(metrics)
	}

	if len(randomFamFoo) > maxVal {
		maxVal = len(randomFamFoo)
	}

	if len(randomFamBar) > maxVal {
		maxVal = len(randomFamBar)
	}

	multiFams := make([][]*pb.MetricFamily, maxVal)
	for i := range maxVal {
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
	if metrics[0][0].GetGauge() != nil {
		typ = pb.MetricType_GAUGE
	}

	var maxVal int
	for _, series := range metrics {
		if len(series) > maxVal {
			maxVal = len(series)
		}
	}

	resp := make([]*pb.MetricFamily, maxVal)

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

func genHistogram(labels []*pb.LabelPair, sumCount ...float64) []*pb.Metric {
	if len(sumCount)%2 != 0 {
		panic("must have even number of sum/count pairs")
	}

	var resp []*pb.Metric

	for i := 0; i < len(sumCount); i += 2 {
		ts := startTime.Add(time.Duration(i/2) * time.Second).UnixMilli()
		sum := sumCount[i]
		count := uint64(sumCount[i+1])
		typ := pb.MetricType_HISTOGRAM

		resp = append(resp, &pb.Metric{
			Label: labels,
			Histogram: &pb.Histogram{
				SampleSum:   &sum,
				SampleCount: &count,
			},
			TimestampMs: &ts,
		})

		_ = typ
	}

	return resp
}

func genHistFam(name string, metrics ...[]*pb.Metric) []*pb.MetricFamily {
	typ := pb.MetricType_HISTOGRAM

	var maxVal int
	for _, series := range metrics {
		if len(series) > maxVal {
			maxVal = len(series)
		}
	}

	resp := make([]*pb.MetricFamily, maxVal)

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

func genGaugef(labels []*pb.LabelPair, values ...float64) []*pb.Metric {
	var resp []*pb.Metric

	for i, value := range values {
		ts := startTime.Add(time.Duration(i) * time.Second).UnixMilli()
		val := value
		resp = append(resp, &pb.Metric{
			Label:       labels,
			Gauge:       &pb.Gauge{Value: &val},
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
