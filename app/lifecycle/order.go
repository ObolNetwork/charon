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
	StartAggSigDB
	StartRelay
	StartMonitoringAPI
	StartValidatorAPI
	StartP2PPing
	StartP2PConsensus
	StartSimulator
	StartScheduler
)

// Global ordering of stop hooks; follows dependency tree from root to leaves.
const (
	StopScheduler OrderStop = iota // High level components...
	StopRetryer
	StopDutyDB
	StopBeaconMock // Close this before validator API, since it can hold long-lived connections.
	StopValidatorAPI
	StopTracing // Low level services...
	StopP2PPeerDB
	StopP2PTCPNode
	StopP2PUDPNode
	StopMonitoringAPI
)
