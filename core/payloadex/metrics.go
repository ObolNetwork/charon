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
)
