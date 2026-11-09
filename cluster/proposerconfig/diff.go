// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"strings"

	"github.com/obolnetwork/charon/cluster"
)

// Diff returns the fields that differ between a and b as "field: old -> new" lines, empty values as "none": the
// default gas limit and builder fields first, then each lock validator whose effective fee recipient differs, in
// lock order.
func Diff(lock cluster.Lock, a, b Config) []string {
	orNone := func(s string) string {
		if s == "" {
			return "none"
		}

		return s
	}

	var lines []string

	add := func(field, oldVal, newVal string) {
		if oldVal != newVal {
			lines = append(lines, field+": "+orNone(oldVal)+" -> "+orNone(newVal))
		}
	}

	add("default.gas_limit", a.DefaultConfig.GasLimit, b.DefaultConfig.GasLimit)

	oldB, newB := builderFields(a.DefaultConfig.Builder), builderFields(b.DefaultConfig.Builder)
	add("default.builder.urls", oldB[0], newB[0])
	add("default.builder.min_bid", oldB[1], newB[1])
	add("default.builder.boost_factor", oldB[2], newB[2])
	add("default.builder.max_execution_payment", oldB[3], newB[3])

	oldFees, newFees := a.FeeRecipients(lock), b.FeeRecipients(lock)
	for i, val := range lock.Validators {
		add("validator "+pubkeyHex(val.PubKey)+".fee_recipient", oldFees[i], newFees[i])
	}

	return lines
}

// builderFields returns the comma-joined urls, min bid, boost factor and max execution payment,
// all empty for a nil builder.
func builderFields(b *Builder) [4]string {
	if b == nil {
		return [4]string{}
	}

	urls := make([]string, 0, len(b.Builders))
	for _, e := range b.Builders {
		urls = append(urls, e.URL)
	}

	return [4]string{strings.Join(urls, ","), b.MinBid, b.BuilderBoostFactor, b.MaxExecutionPayment}
}
