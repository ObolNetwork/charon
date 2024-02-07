// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

// rate object tracks total/count values to calculate the final rate in %%.
type rate struct {
	total int
	count int
}

// incrementTotal() increments the total value.
func (r *rate) incrementTotal() {
	r.total++
}

// incrementCount() increments the count value.
func (r *rate) incrementCount() {
	r.count++
}

// getRate() returns the calculated rate in percent.
func (r rate) getRate() float64 {
	if r.total == 0 {
		return 0
	}

	return float64(r.count) * 100.0 / float64(r.total)
}
