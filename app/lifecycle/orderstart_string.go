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

// Code generated by "stringer -type=OrderStart -trimprefix=Start"; DO NOT EDIT.

package lifecycle

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StartAggSigDB-0]
	_ = x[StartMonitoringAPI-1]
	_ = x[StartValidatorAPI-2]
	_ = x[StartP2PPing-3]
	_ = x[StartLeaderCast-4]
	_ = x[StartSimulator-5]
	_ = x[StartScheduler-6]
}

const _OrderStart_name = "AggSigDBMonitoringAPIValidatorAPIP2PPingLeaderCastSimulatorScheduler"

var _OrderStart_index = [...]uint8{0, 8, 21, 33, 40, 50, 59, 68}

func (i OrderStart) String() string {
	if i < 0 || i >= OrderStart(len(_OrderStart_index)-1) {
		return "OrderStart(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _OrderStart_name[_OrderStart_index[i]:_OrderStart_index[i+1]]
}
