// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"slices"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// ErrNoChange is returned by Apply and ApplyProposal when the result equals the current config.
var ErrNoChange = errors.New("proposer config is unchanged")

// Delta is a set of changes to a Config. Zero values mean "not set": nil FeeRecipients, a zero GasLimit, nil
// BuilderURLs and builder pointers, and a false NoBuilders. FeeRecipients holds one address per DV pubkey in
// FeeRecipientValidators, in order, or with AllValidators a single address for every validator.
type Delta struct {
	FeeRecipientValidators     []string
	FeeRecipients              []string
	AllValidators              bool
	GasLimit                   uint64
	BuilderURLs                []string
	BuilderMinBid              *uint64
	BuilderBoostFactor         *uint64
	BuilderMaxExecutionPayment *uint64
	NoBuilders                 bool
}

// Apply returns the config with the delta applied, or ErrNoChange if the result equals c.
func Apply(lock cluster.Lock, c Config, d Delta) (Config, error) {
	fees, defaultFee, err := applyFeeRecipients(lock, c, d)
	if err != nil {
		return Config{}, err
	}

	gasLimit, err := c.GasLimit()
	if err != nil {
		return Config{}, err
	}

	if d.GasLimit != 0 {
		gasLimit = d.GasLimit
	}

	if d.NoBuilders && (d.BuilderURLs != nil || d.BuilderMinBid != nil || d.BuilderBoostFactor != nil || d.BuilderMaxExecutionPayment != nil) {
		return Config{}, errors.New("no builders excludes the other builder fields")
	}

	if d.BuilderURLs != nil && len(d.BuilderURLs) == 0 {
		return Config{}, errors.New("builder urls must not be empty, set no builders to remove the builders")
	}

	var builder *Builder

	switch {
	case d.NoBuilders:
	case c.DefaultConfig.Builder == nil && d.BuilderURLs == nil:
		if d.BuilderMinBid != nil || d.BuilderBoostFactor != nil || d.BuilderMaxExecutionPayment != nil {
			return Config{}, errors.New("builder min bid, boost factor and max execution payment require builder urls")
		}
	default:
		builder, err = applyBuilder(c.DefaultConfig.Builder, d)
		if err != nil {
			return Config{}, err
		}
	}

	res, err := NewConfigWithDefault(lock, defaultFee, fees, gasLimit, builder)
	if err != nil {
		return Config{}, err
	}

	equal, err := SameConfig(c, res)
	if err != nil {
		return Config{}, err
	}

	if equal {
		return Config{}, ErrNoChange
	}

	return res, nil
}

// applyFeeRecipients returns the validators' fee recipients in lock order and the default fee recipient with
// the delta applied. All validators moves the default too, listed validators leave it as is.
func applyFeeRecipients(lock cluster.Lock, c Config, d Delta) ([]string, string, error) {
	fees := c.FeeRecipients(lock)
	defaultFee := c.DefaultConfig.FeeRecipient

	if d.AllValidators {
		if len(d.FeeRecipientValidators) != 0 || len(d.FeeRecipients) != 1 {
			return nil, "", errors.New("all validators takes a single fee recipient and no validators")
		}

		fee, err := normaliseAddress(d.FeeRecipients[0])
		if err != nil {
			return nil, "", err
		}

		for i := range fees {
			fees[i] = fee
		}

		return fees, fee, nil
	}

	if len(d.FeeRecipientValidators) != len(d.FeeRecipients) {
		return nil, "", errors.New("mismatching number of validators and fee recipients",
			z.Int("validators", len(d.FeeRecipientValidators)), z.Int("fee_recipients", len(d.FeeRecipients)))
	}

	seen := make(map[int]bool)

	for i, pubkey := range d.FeeRecipientValidators {
		fee, err := normaliseAddress(d.FeeRecipients[i])
		if err != nil {
			return nil, "", err
		}

		pubkey = strings.ToLower(pubkey)
		if !strings.HasPrefix(pubkey, "0x") {
			pubkey = "0x" + pubkey
		}

		idx := slices.IndexFunc(lock.Validators, func(v cluster.DistValidator) bool {
			return pubkeyHex(v.PubKey) == pubkey
		})
		if idx < 0 {
			return nil, "", errors.New("validator not in lock", z.Str("pubkey", pubkey))
		}

		if seen[idx] {
			return nil, "", errors.New("duplicate validator", z.Str("pubkey", pubkey))
		}

		seen[idx] = true
		fees[idx] = fee
	}

	return fees, defaultFee, nil
}

// applyBuilder returns the builder with the delta applied without mutating b; a nil b starts from the defaults.
func applyBuilder(b *Builder, d Delta) (*Builder, error) {
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

	if d.BuilderURLs != nil {
		err := validateBuilderURLs("builder-urls", d.BuilderURLs)
		if err != nil {
			return nil, err
		}

		res.Builders = make([]BuilderEntry, 0, len(d.BuilderURLs))
		for _, u := range d.BuilderURLs {
			res.Builders = append(res.Builders, BuilderEntry{URL: u})
		}
	}

	if d.BuilderMinBid != nil {
		res.MinBid = strconv.FormatUint(*d.BuilderMinBid, 10)
	}

	if d.BuilderBoostFactor != nil {
		if *d.BuilderBoostFactor == 0 {
			return nil, errors.New("builder boost factor must be greater than 0")
		}

		res.BuilderBoostFactor = strconv.FormatUint(*d.BuilderBoostFactor, 10)
	}

	if d.BuilderMaxExecutionPayment != nil {
		res.MaxExecutionPayment = strconv.FormatUint(*d.BuilderMaxExecutionPayment, 10)
	}

	return &res, nil
}

// SameConfig returns whether a and b have the same canonical form, comparing their hashes under one lock hash.
func SameConfig(a, b Config) (bool, error) {
	lockHash := make([]byte, sszLenHash)

	ha, err := Document{LockHash: lockHash, Config: a}.Hash()
	if err != nil {
		return false, err
	}

	hb, err := Document{LockHash: lockHash, Config: b}.Hash()
	if err != nil {
		return false, err
	}

	return ha == hb, nil
}
