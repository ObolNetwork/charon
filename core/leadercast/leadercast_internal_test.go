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

package leadercast

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestIsLeader(t *testing.T) {
	tests := []struct {
		Slot          int64
		DutyType      core.DutyType
		Leader, Total int
	}{
		{
			Slot:     1,
			DutyType: 1,
			Total:    5,
			Leader:   2,
		}, {
			Slot:     1,
			DutyType: 2,
			Total:    5,
			Leader:   3,
		}, {
			Slot:     1,
			DutyType: 3,
			Total:    5,
			Leader:   4,
		}, {
			Slot:     1,
			DutyType: 1,
			Total:    2,
			Leader:   0,
		}, {
			Slot:     2,
			DutyType: 1,
			Total:    2,
			Leader:   1,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for i := 0; i < test.Total; i++ {
				ok := isLeader(i, test.Total, core.Duty{
					Slot: test.Slot,
					Type: test.DutyType,
				})
				if i == test.Leader && !ok {
					require.Fail(t, "Expected leader", i)
				} else if i != test.Leader && ok {
					require.Fail(t, "Unexpected leader", i)
				}
			}
		})
	}
}
