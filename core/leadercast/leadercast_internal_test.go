// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package leadercast

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

func TestIsLeader(t *testing.T) {
	tests := []struct {
		Slot          uint64
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
