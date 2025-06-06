// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	// AggSigDBV2 enables a newer, simpler implementation of `aggsigdb`.
	AggSigDBV2 Feature = "aggsigdb_v2"

	// JSONRequests enables JSON requests for eth2 client.
	JSONRequests Feature = "json_requests"

	// GnosisBlockHotfix enables Gnosis/Chiado SSZ fix.
	// The feature gets automatically enabled when the current network is gnosis|chiado,
	// unless the user disabled this feature explicitly.
	GnosisBlockHotfix Feature = "gnosis_block_hotfix"

	// Linear enables Linear round timer for consensus rounds.
	// When active has precedence over EagerDoubleLinear round timer.
	Linear Feature = "linear"

	// SSEReorgDuties enables Scheduler to refresh duties when reorg occurs.
	SSEReorgDuties Feature = "sse_reorg_duties"

	// AttestationInclusion enables tracking of on-chain inclusion for attestations.
	// Previously this was the default behaviour, however, tracking on-chain inclusions post-electra is costly.
	// The extra load that Charon puts the beacon node is deemed so high that it can throttle the completion of other duties.
	AttestationInclusion Feature = "attestation_inclusion"
)

var (
	// state defines the current rollout status of each feature.
	state = map[Feature]status{
		EagerDoubleLinear:    statusStable,
		ConsensusParticipate: statusStable,
		MockAlpha:            statusAlpha,
		AggSigDBV2:           statusAlpha,
		JSONRequests:         statusAlpha,
		GnosisBlockHotfix:    statusAlpha,
		Linear:               statusAlpha,
		SSEReorgDuties:       statusAlpha,
		AttestationInclusion: statusAlpha,
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
