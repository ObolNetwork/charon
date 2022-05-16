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
	// DKG introduces Frost DKG algorithm into charon.
	DKG Feature = "dkg"
)

var (
	// state defines the current rollout status of each feature.
	state = map[Feature]status{
		QBFTConsensus: statusAlpha,
		DKG:           statusAlpha,
		// Add all features and there status here.
	}

	// minStatus defines the minimum enabled status.
	minStatus = statusStable
)

// Enabled returns true if the feature is enabled.
func Enabled(feature Feature) bool {
	return state[feature] >= minStatus
}
