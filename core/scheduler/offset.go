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

package scheduler

import (
	"time"

	"github.com/obolnetwork/charon/core"
)

// slotOffsets defines the offsets at which the duties should be triggered.
var slotOffsets = map[core.DutyType]func(time.Duration) time.Duration{
	core.DutyAttester:         fraction(1, 3), // 1/3 slot duration
	core.DutyAggregator:       fraction(2, 3), // 2/3 slot duration
	core.DutySyncContribution: fraction(2, 3), // 2/3 slot duration
	// TODO(corver): Add more duties
}

// fraction returns a function that calculates slot offset based on the fraction x/y of total slot duration.
func fraction(x, y int64) func(time.Duration) time.Duration {
	return func(total time.Duration) time.Duration {
		return (total * time.Duration(x)) / time.Duration(y)
	}
}
