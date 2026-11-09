// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const addrC = "0x000000000000000000000000000000000000000c"

func testBuilder() *Builder {
	return &Builder{
		MinBid:              "5",
		BuilderBoostFactor:  "110",
		MaxExecutionPayment: "7",
		Builders:            []BuilderEntry{{URL: "https://b1.example"}},
	}
}

func TestApplyFeeRecipientAll(t *testing.T) {
	lock := testLock(t, 3)
	c, err := NewConfig(lock, []string{addrA, addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{FeeRecipient: "0x" + strings.ToUpper(addrC[2:])})
	require.NoError(t, err)
	require.Equal(t, []string{addrC, addrC, addrC}, res.FeeRecipients(lock))
	require.Empty(t, res.ProposerConfig)
	// The input is untouched.
	require.Equal(t, []string{addrA, addrA, addrB}, c.FeeRecipients(lock))
}

func TestApplyFeeRecipientSubset(t *testing.T) {
	lock := testLock(t, 3)
	c, err := NewConfig(lock, []string{addrA, addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)

	// Flips the majority: validators 0 and 1 move to B, validator 2 stays on B.
	v0 := pubkeyHex(lock.Validators[0].PubKey)
	v1 := strings.ToUpper(pubkeyHex(lock.Validators[1].PubKey)[2:])

	res, err := Apply(lock, c, Delta{FeeRecipient: addrB, FeeRecipientValidators: []string{v0, "0x" + v1}})
	require.NoError(t, err)
	require.Equal(t, []string{addrB, addrB, addrB}, res.FeeRecipients(lock))
	require.Empty(t, res.ProposerConfig)

	// Only touched validators are listed even though the default flipped.
	require.Equal(t, []string{
		"validator " + v0 + ".fee_recipient: " + addrA + " -> " + addrB,
		"validator " + pubkeyHex(lock.Validators[1].PubKey) + ".fee_recipient: " + addrA + " -> " + addrB,
	}, Diff(lock, c, res))
}

func TestApplyGasLimit(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{GasLimit: 60_000_000})
	require.NoError(t, err)
	require.Equal(t, "60000000", res.DefaultConfig.GasLimit)
}

func TestApplyBuilderURLsCreatesBlock(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{BuilderURLs: []string{"https://b2.example", "https://b1.example"}})
	require.NoError(t, err)
	require.Equal(t, &Builder{
		MinBid:              "0",
		BuilderBoostFactor:  "100",
		MaxExecutionPayment: "0",
		Builders:            []BuilderEntry{{URL: "https://b2.example"}, {URL: "https://b1.example"}},
	}, res.DefaultConfig.Builder)

	// The edit command's flag is bare, unlike the run seeding flag.
	_, err = Apply(lock, c, Delta{BuilderURLs: []string{"ftp://nope"}})
	require.ErrorContains(t, err, "builder-urls entry is not a valid http(s) URL")
	require.NotContains(t, err.Error(), "proposer-config-")
}

func TestApplyBuilderFieldDelta(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{BuilderMinBid: new(uint64(9))})
	require.NoError(t, err)
	require.Equal(t, &Builder{
		MinBid:              "9",
		BuilderBoostFactor:  "110",
		MaxExecutionPayment: "7",
		Builders:            []BuilderEntry{{URL: "https://b1.example"}},
	}, res.DefaultConfig.Builder)
	require.Equal(t, "5", c.DefaultConfig.Builder.MinBid)

	// URLs replace the list and keep the fields.
	res, err = Apply(lock, c, Delta{BuilderURLs: []string{"https://b3.example"}})
	require.NoError(t, err)
	require.Equal(t, "110", res.DefaultConfig.Builder.BuilderBoostFactor)
	require.Equal(t, []BuilderEntry{{URL: "https://b3.example"}}, res.DefaultConfig.Builder.Builders)
}

func TestApplyBuilderFieldWithoutBlock(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	for _, d := range []Delta{
		{BuilderMinBid: new(uint64(1))},
		{BuilderBoostFactor: new(uint64(1))},
		{BuilderMaxExecutionPayment: new(uint64(1))},
	} {
		_, err = Apply(lock, c, d)
		require.ErrorContains(t, err, "require builder urls")
	}

	// With URLs in the same delta they apply on top of the defaults.
	res, err := Apply(lock, c, Delta{BuilderURLs: []string{"https://b1.example"}, BuilderBoostFactor: new(uint64(50))})
	require.NoError(t, err)
	require.Equal(t, "50", res.DefaultConfig.Builder.BuilderBoostFactor)

	_, err = Apply(lock, c, Delta{BuilderURLs: []string{"https://b1.example"}, BuilderBoostFactor: new(uint64(0))})
	require.ErrorContains(t, err, "boost factor")
}

func TestApplyNoBuilders(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{NoBuilders: true})
	require.NoError(t, err)
	require.Nil(t, res.DefaultConfig.Builder)
	require.NotNil(t, c.DefaultConfig.Builder)
}

func TestApplyCombined(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	res, err := Apply(lock, c, Delta{GasLimit: 1, BuilderURLs: []string{"https://b1.example"}})
	require.NoError(t, err)
	require.Equal(t, "1", res.DefaultConfig.GasLimit)
	require.Len(t, res.DefaultConfig.Builder.Builders, 1)
}

func TestApplyNoChange(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrB}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	for _, d := range []Delta{
		{},
		{GasLimit: DefaultGasLimit},
		{BuilderURLs: []string{"https://b1.example"}, BuilderMinBid: new(uint64(5))},
		{FeeRecipient: addrB, FeeRecipientValidators: []string{pubkeyHex(lock.Validators[1].PubKey)}},
	} {
		_, err = Apply(lock, c, d)
		require.ErrorIs(t, err, ErrNoChange)
	}

	// NoBuilders on config without builders is a no-op next to a real change.
	nb, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	_, err = Apply(lock, nb, Delta{NoBuilders: true})
	require.ErrorIs(t, err, ErrNoChange)

	res, err := Apply(lock, nb, Delta{NoBuilders: true, GasLimit: 5})
	require.NoError(t, err)
	require.Equal(t, "5", res.DefaultConfig.GasLimit)
}

func TestApplyUnknownValidator(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	unknown := "0x" + strings.Repeat("ab", 48)

	_, err = Apply(lock, c, Delta{FeeRecipient: addrB, FeeRecipientValidators: []string{unknown}})
	require.ErrorContains(t, err, unknown)
}

func TestApplyInvalidFeeRecipient(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	_, err = Apply(lock, c, Delta{FeeRecipient: "0x123"})
	require.Error(t, err)
}

func TestApplyDuplicateBuilderURLs(t *testing.T) {
	lock := testLock(t, 1)
	c, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	_, err = Apply(lock, c, Delta{BuilderURLs: []string{"https://a.example", "https://a.example"}})
	require.ErrorContains(t, err, "builder-urls entry is duplicated")
}
