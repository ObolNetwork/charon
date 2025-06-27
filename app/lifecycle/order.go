// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package lifecycle

//go:generate stringer -type=OrderStart -trimprefix=Start
//go:generate stringer -type=OrderStop -trimprefix=Stop

// OrderStart defines the order hooks are started.
type OrderStart int

// OrderStop defines the order hooks are stopped.
type OrderStop int

// Global ordering of start hooks.
const (
	StartTracker OrderStart = iota
	StartPrivkeyLock
	StartAggSigDB
	StartRelay
	StartMonitoringAPI
	StartDebugAPI
	StartValidatorAPI
	StartP2PPing
	StartP2PRouters
	StartForceDirectConns
	StartP2PConsensus
	StartSimulator
	StartScheduler
	StartP2PEventCollector
	StartPeerInfo
	StartParSigDB
	StartStackSnipe
)

// Global ordering of stop hooks; follows dependency tree from root to leaves.
const (
	StopScheduler OrderStop = iota // High level components...
	StopPrivkeyLock
	StopRetryer
	StopDutyDB
	StopBeaconMock // Close this before validator API, since it can hold long-lived connections.
	StopValidatorAPI
	StopTracing // Low level services...
	StopP2PPeerDB
	StopP2PNode
	StopDebugAPI
	StopMonitoringAPI
)
