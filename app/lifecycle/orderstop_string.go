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

// Code generated by "stringer -type=OrderStop -trimprefix=Stop"; DO NOT EDIT.

package lifecycle

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StopScheduler-0]
	_ = x[StopRetryer-1]
	_ = x[StopDutyDB-2]
	_ = x[StopBeaconMock-3]
	_ = x[StopValidatorAPI-4]
	_ = x[StopTracing-5]
	_ = x[StopP2PPeerDB-6]
	_ = x[StopP2PTCPNode-7]
	_ = x[StopP2PUDPNode-8]
	_ = x[StopMonitoringAPI-9]
}

const _OrderStop_name = "SchedulerRetryerDutyDBBeaconMockValidatorAPITracingP2PPeerDBP2PTCPNodeP2PUDPNodeMonitoringAPI"

var _OrderStop_index = [...]uint8{0, 9, 16, 22, 32, 44, 51, 60, 70, 80, 93}

func (i OrderStop) String() string {
	if i < 0 || i >= OrderStop(len(_OrderStop_index)-1) {
		return "OrderStop(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _OrderStop_name[_OrderStop_index[i]:_OrderStop_index[i+1]]
}
