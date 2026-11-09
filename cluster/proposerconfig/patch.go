// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"slices"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// ErrNoChange is returned by Apply when the patch leaves the content unchanged.
var ErrNoChange = errors.New("patch does not change the proposer config")

// FieldDiff is one differing field between two contents.
type FieldDiff struct {
	Field string
	Old   string
	New   string
}

// Patch is a set of changes to a Content. Zero values mean "not set": an empty FeeRecipient, a zero
// GasLimit, nil BuilderURLs and builder pointers, and a false NoBuilders. An empty FeeRecipientValidators
// applies the fee recipient to all validators.
type Patch struct {
	FeeRecipient               string
	FeeRecipientValidators     []string
	GasLimit                   uint64
	BuilderURLs                []string
	BuilderMinBid              *uint64
	BuilderBoostFactor         *uint64
	BuilderMaxExecutionPayment *uint64
	NoBuilders                 bool
}

// Diff returns the field differences between a and b: the default gas limit and builder fields first,
// then each lock validator whose effective fee recipient differs, in lock order.
func Diff(lock cluster.Lock, a, b Content) []FieldDiff {
	var res []FieldDiff

	add := func(field, oldVal, newVal string) {
		if oldVal != newVal {
			res = append(res, FieldDiff{Field: field, Old: oldVal, New: newVal})
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

	return res
}

// FormatDiffs returns the differing fields as "field: old -> new" lines, empty values as "none".
func FormatDiffs(diffs []FieldDiff) []string {
	orNone := func(s string) string {
		if s == "" {
			return "none"
		}

		return s
	}

	var lines []string

	for _, d := range diffs {
		if d.Old == d.New {
			continue
		}

		lines = append(lines, d.Field+": "+orNone(d.Old)+" -> "+orNone(d.New))
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

// Apply returns the content with the patch applied, or ErrNoChange if the result equals c.
func Apply(lock cluster.Lock, c Content, p Patch) (Content, error) {
	fees := c.FeeRecipients(lock)

	if p.FeeRecipient != "" {
		var err error

		fees, err = patchFeeRecipients(lock, fees, p)
		if err != nil {
			return Content{}, err
		}
	}

	gasLimit, err := c.GasLimit()
	if err != nil {
		return Content{}, err
	}

	if p.GasLimit != 0 {
		gasLimit = p.GasLimit
	}

	var builder *Builder

	switch {
	case p.NoBuilders:
	case c.DefaultConfig.Builder == nil && p.BuilderURLs == nil:
		if p.BuilderMinBid != nil || p.BuilderBoostFactor != nil || p.BuilderMaxExecutionPayment != nil {
			return Content{}, errors.New("builder min bid, boost factor and max execution payment require builder urls")
		}
	default:
		builder, err = patchBuilder(c.DefaultConfig.Builder, p)
		if err != nil {
			return Content{}, err
		}
	}

	res, err := NewContent(lock, fees, gasLimit, builder)
	if err != nil {
		return Content{}, err
	}

	equal, err := sameContent(c, res)
	if err != nil {
		return Content{}, err
	}

	if equal {
		return Content{}, ErrNoChange
	}

	return res, nil
}

// patchFeeRecipients returns a copy of fees with the patch's fee recipient set on the selected validators.
func patchFeeRecipients(lock cluster.Lock, fees []string, p Patch) ([]string, error) {
	fee, err := normaliseAddress(p.FeeRecipient)
	if err != nil {
		return nil, err
	}

	res := slices.Clone(fees)

	if len(p.FeeRecipientValidators) == 0 {
		for i := range res {
			res[i] = fee
		}

		return res, nil
	}

	for _, pubkey := range p.FeeRecipientValidators {
		pubkey = strings.ToLower(pubkey)
		if !strings.HasPrefix(pubkey, "0x") {
			pubkey = "0x" + pubkey
		}

		idx := slices.IndexFunc(lock.Validators, func(v cluster.DistValidator) bool {
			return pubkeyHex(v.PubKey) == pubkey
		})
		if idx < 0 {
			return nil, errors.New("validator not in lock: " + pubkey)
		}

		res[idx] = fee
	}

	return res, nil
}

// patchBuilder returns the builder with the patch applied without mutating b; a nil b starts from the defaults.
func patchBuilder(b *Builder, p Patch) (*Builder, error) {
	var res Builder

	if b != nil {
		res = *b
		res.Builders = slices.Clone(b.Builders)
	} else {
		res = Builder{
			MinBid:              "0",
			BuilderBoostFactor:  strconv.FormatUint(DefaultBuilderBoostFactor, 10),
			MaxExecutionPayment: "0",
		}
	}

	if p.BuilderURLs != nil {
		err := validateBuilderURLs("builder-urls", p.BuilderURLs)
		if err != nil {
			return nil, err
		}

		res.Builders = make([]BuilderEntry, 0, len(p.BuilderURLs))
		for _, u := range p.BuilderURLs {
			res.Builders = append(res.Builders, BuilderEntry{URL: u})
		}
	}

	if p.BuilderMinBid != nil {
		res.MinBid = strconv.FormatUint(*p.BuilderMinBid, 10)
	}

	if p.BuilderBoostFactor != nil {
		if *p.BuilderBoostFactor == 0 {
			return nil, errors.New("builder boost factor must be greater than 0")
		}

		res.BuilderBoostFactor = strconv.FormatUint(*p.BuilderBoostFactor, 10)
	}

	if p.BuilderMaxExecutionPayment != nil {
		res.MaxExecutionPayment = strconv.FormatUint(*p.BuilderMaxExecutionPayment, 10)
	}

	return &res, nil
}

// sameContent returns whether a and b have the same canonical form.
func sameContent(a, b Content) (bool, error) {
	ha, err := Document{Content: a}.Hash()
	if err != nil {
		return false, err
	}

	hb, err := Document{Content: b}.Hash()
	if err != nil {
		return false, err
	}

	return ha == hb, nil
}
