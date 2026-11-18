// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/log"
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

	oldB, newB := flattenBuilder(a.DefaultConfig.Builder), flattenBuilder(b.DefaultConfig.Builder)
	if !slices.Equal(oldB.urls, newB.urls) {
		// Compared raw, shown redacted: builder URLs may carry credentials.
		lines = append(lines, "default.builder.urls: "+orNone(RedactURLs(oldB.urls))+" -> "+orNone(RedactURLs(newB.urls)))
	}

	add("default.builder.min_bid", oldB.minBid, newB.minBid)
	add("default.builder.boost_factor", oldB.boostFactor, newB.boostFactor)
	add("default.builder.max_execution_payment", oldB.maxExecutionPayment, newB.maxExecutionPayment)

	oldFees, newFees := a.FeeRecipients(lock), b.FeeRecipients(lock)
	for i, val := range lock.Validators {
		add("validator "+pubkeyHex(val.PubKey)+".fee_recipient", oldFees[i], newFees[i])
	}

	return lines
}

// RedactURLs returns the URLs redacted as the URL flags are logged, comma-joined for display. The URLs are
// redacted one by one: a URL may itself contain a comma.
func RedactURLs(urls []string) string {
	return strings.Join(log.RedactURLs(urls, true), ",")
}

// builderValues are a builder's settings as strings, all empty for a nil builder.
type builderValues struct {
	urls                []string
	minBid              string
	boostFactor         string
	maxExecutionPayment string
}

// flattenBuilder returns the builder's values.
func flattenBuilder(b *Builder) builderValues {
	if b == nil {
		return builderValues{}
	}

	urls := make([]string, 0, len(b.Builders))
	for _, e := range b.Builders {
		urls = append(urls, e.URL)
	}

	return builderValues{urls: urls, minBid: b.MinBid, boostFactor: b.BuilderBoostFactor, maxExecutionPayment: b.MaxExecutionPayment}
}
