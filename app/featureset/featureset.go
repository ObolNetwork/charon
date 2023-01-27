// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	// QBFTConsensus introduces qbft consensus, see https://github.com/ObolNetwork/charon/issues/445.
	QBFTConsensus Feature = "qbft_consensus"
	// Priority enables the infosync component using the priority protocol.
	Priority Feature = "priority"
	// MockAlpha is a mock feature in alpha status for testing.
	MockAlpha Feature = "mock_alpha"

	// RelayDiscovery enables relay peer discovery and disables discv5:
	//   - If a direct connection to a peer is not possible then try to connect to it via all the provided bootnodes/relays.
	//   - Direct connections are either not possible since no addresses are known or the addresses do not work.
	//   - When connected via relay, libp2p's identify protocol detects the remote peer's addresses.
	//   - Those are added to the peer store so libp2p will try to use them.
	RelayDiscovery Feature = "relay_discovery"

	// HerumiBLS enables usage of the Herumi BLS12-381 implementation, rather than Kryptology.
	HerumiBLS Feature = "herumi_bls"

	// TrackerV2 enables support of tracker2.
	// TODO(dhruv): remove this featureflag once we are more confident about tracker2.
	TrackerV2 Feature = "tracker_v2"
)

var (
	// state defines the current rollout status of each feature.
	state = map[Feature]status{
		QBFTConsensus:  statusStable,
		Priority:       statusStable,
		MockAlpha:      statusAlpha,
		RelayDiscovery: statusStable,
		HerumiBLS:      statusBeta,
		TrackerV2:      statusAlpha,
		// Add all features and there status here.
	}

	// minStatus defines the minimum enabled status.
	minStatus = statusStable

	initMu sync.Mutex
)

// Enabled returns true if the feature is enabled.
func Enabled(feature Feature) bool {
	return state[feature] >= minStatus
}
