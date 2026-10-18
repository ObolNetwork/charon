// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package payloadex

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	sharedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "shared_total",
		Help:      "Total number of agreed self-built proposals whose execution payload contents this node shared with its peers",
	})

	receivedCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "received_total",
		Help:      "Total number of execution payload contents received from peers, pushed or requested, by result (accepted or rejected)",
	}, []string{"result"})

	requestedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "requested_total",
		Help:      "Total number of agreed self-built proposals whose execution payload contents this node had to request from its peers, the proposer's push not having arrived in time",
	})

	servedCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "served_total",
		Help:      "Total number of execution payload contents requests from peers, by result (found or missing)",
	}, []string{"result"})

	envelopeSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "envelope_size_bytes",
		Help:      "Size of the execution payload envelope of agreed self-built proposals shared by this node",
		Buckets:   []float64{50e3, 100e3, 150e3, 200e3, 250e3, 300e3, 400e3, 500e3, 750e3, 1e6, 2e6, 4e6, 8e6},
	})

	blobsPerProposal = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "blobs_per_proposal",
		Help:      "Number of blobs of agreed self-built proposals shared by this node, each 128 KiB plus 6 KiB of KZG proofs on the wire",
		Buckets:   []float64{0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 18, 21},
	})

	contentsDelay = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "payloadex",
		Name:      "contents_delay_seconds",
		Help:      "Delay from this node's decision on an agreed self-built proposal until it holds the execution payload contents, by source (pushed by the proposer or requested from peers)",
		Buckets:   []float64{.05, .1, .25, .5, .75, 1, 1.5, 2, 3, 5, 8},
	}, []string{"source"})
)
