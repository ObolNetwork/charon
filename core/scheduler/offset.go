// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package scheduler

import (
	"time"

	"github.com/obolnetwork/charon/core"
)

// slotOffsets defines the offsets at which the duties should be triggered.
var slotOffsets = map[core.DutyType]func(time.Duration) time.Duration{
	core.DutyAttester:         fraction(1, 3), // 1/3 slot duration
	core.DutyAggregator:       fraction(2, 3), // 2/3 slot duration
	core.DutySyncContribution: fraction(2, 3),
}

// fraction returns a function that calculates slot offset based on the fraction x/y of total slot duration.
func fraction(x, y int64) func(time.Duration) time.Duration {
	return func(total time.Duration) time.Duration {
		return (total * time.Duration(x)) / time.Duration(y)
	}
}
