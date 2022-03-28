// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lifecycle

//go:generate stringer -type=OrderStart -trimprefix=Start
//go:generate stringer -type=OrderStop -trimprefix=Stop

// OrderStart defines the order hooks are started.
type OrderStart int

// OrderStop defines the order hooks are stopped.
type OrderStop int

// Global ordering of start and stop hooks.
const (
	StartAggSigDB OrderStart = iota
	StartMonitoringAPI
	StartValidatorAPI
	StartP2PPing
	StartLeaderCast
	StartSimulator
	StartScheduler

	StopTracing OrderStop = iota
	StopScheduler
	StopP2PPeerDB
	StopP2PTCPNode
	StopP2PUDPNode
	StopMonitoringAPI
	StopValidatorAPI
)
