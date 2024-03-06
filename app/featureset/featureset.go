// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package featureset defines a set of global features and their rollout status.
package featureset

import "sync"

//go:generate stringer -type=status -trimprefix=status

// status enumerates the rollout status of a feature.
type status int

const (
	// statusAlpha is for internal devnet testing.
	statusAlpha status = iota + 1
	// statusBeta is for internal and external testnet testing.
	statusBeta
	// statusStable is for stable feature ready for production.
	statusStable
	// statusSentinel is an internal tail-end placeholder.
	statusSentinel // Must always be last
)

// Feature is a feature being rolled out.
type Feature string

const (
	// MockAlpha is a mock feature in alpha status for testing.
	MockAlpha Feature = "mock_alpha"

	// EagerDoubleLinear enables Eager Double Linear round timer for consensus rounds.
	EagerDoubleLinear Feature = "eager_double_linear"

	// ConsensusParticipate enables consensus participate feature in order to participate in an ongoing consensus
	// round while still waiting for an unsigned data from beacon node.
	ConsensusParticipate Feature = "consensus_participate"

	AggSigDBV2 Feature = "aggsigdb_v2"
)

var (
	// state defines the current rollout status of each feature.
	state = map[Feature]status{
		MockAlpha:            statusAlpha,
		EagerDoubleLinear:    statusAlpha,
		ConsensusParticipate: statusAlpha,
		AggSigDBV2:           statusAlpha,
		// Add all features and there status here.
	}

	// minStatus defines the minimum enabled status.
	minStatus = statusStable

	initMu sync.Mutex
)

// Enabled returns true if the feature is enabled.
func Enabled(feature Feature) bool {
	initMu.Lock()
	defer initMu.Unlock()

	return state[feature] >= minStatus
}
