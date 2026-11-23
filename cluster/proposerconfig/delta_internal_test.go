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

	// Every validator changes, those with their own fee recipient included, and the default follows.
	res, err := Apply(lock, c, Delta{AllValidators: true, FeeRecipients: []string{"0x" + strings.ToUpper(addrC[2:])}})
	require.NoError(t, err)
	require.Equal(t, addrC, res.DefaultConfig.FeeRecipient)
	require.Equal(t, []string{addrC, addrC, addrC}, res.FeeRecipients(lock))
	require.Empty(t, res.ProposerConfig)
	// The input is untouched.
	require.Equal(t, []string{addrA, addrA, addrB}, c.FeeRecipients(lock))

	require.Equal(t, []string{
		"default.fee_recipient: " + addrA + " -> " + addrC,
		"2 validators.fee_recipient: " + addrA + " -> " + addrC,
		"validator " + pubkeyHex(lock.Validators[2].PubKey) + ".fee_recipient: " + addrB + " -> " + addrC,
	}, Diff(lock, c, res))

	_, err = Apply(lock, res, Delta{AllValidators: true, FeeRecipients: []string{addrC}})
	require.ErrorIs(t, err, ErrNoChange)
}

func TestApplyFeeRecipientBackToDefault(t *testing.T) {
	lock := testLock(t, 3)
	c, err := NewConfig(lock, []string{addrA, addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)

	// A validator set to the default loses its entry.
	res, err := Apply(lock, c, Delta{FeeRecipientValidators: []string{pubkeyHex(lock.Validators[2].PubKey)}, FeeRecipients: []string{addrA}})
	require.NoError(t, err)
	require.Equal(t, addrA, res.DefaultConfig.FeeRecipient)
	require.Empty(t, res.ProposerConfig)
}

func TestApplyFeeRecipientPaired(t *testing.T) {
	lock := testLock(t, 3)
	c, err := NewConfig(lock, []string{addrA, addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)

	v0 := pubkeyHex(lock.Validators[0].PubKey)
	v1 := strings.ToUpper(pubkeyHex(lock.Validators[1].PubKey)[2:])

	// Paired in list order.
	res, err := Apply(lock, c, Delta{FeeRecipientValidators: []string{"0x" + v1, v0}, FeeRecipients: []string{addrC, addrB}})
	require.NoError(t, err)
	require.Equal(t, []string{addrB, addrC, addrB}, res.FeeRecipients(lock))
	// The default stays, even with all validators on another fee recipient.
	require.Equal(t, addrA, res.DefaultConfig.FeeRecipient)
	require.Len(t, res.ProposerConfig, 3)

	require.Equal(t, []string{
		"validator " + v0 + ".fee_recipient: " + addrA + " -> " + addrB,
		"validator " + pubkeyHex(lock.Validators[1].PubKey) + ".fee_recipient: " + addrA + " -> " + addrC,
	}, Diff(lock, c, res))
}

func TestApplyInvalidFeeRecipients(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	v0, v1 := pubkeyHex(lock.Validators[0].PubKey), pubkeyHex(lock.Validators[1].PubKey)

	tests := []struct {
		name    string
		delta   Delta
		wantErr string
	}{
		{"more validators", Delta{FeeRecipientValidators: []string{v0, v1}, FeeRecipients: []string{addrB}}, "mismatching number of validators and fee recipients"},
		{"no validators", Delta{FeeRecipients: []string{addrB}}, "mismatching number of validators and fee recipients"},
		{"duplicate validator", Delta{FeeRecipientValidators: []string{v0, strings.ToUpper(v0[2:])}, FeeRecipients: []string{addrB, addrC}}, "duplicate validator"},
		{"unknown validator", Delta{FeeRecipientValidators: []string{"0x" + strings.Repeat("ab", 48)}, FeeRecipients: []string{addrB}}, "validator not in lock"},
		{"invalid address", Delta{FeeRecipientValidators: []string{v0}, FeeRecipients: []string{"0x123"}}, "validate address"},
		{"all with validators", Delta{AllValidators: true, FeeRecipientValidators: []string{v0}, FeeRecipients: []string{addrB}}, "all validators takes a single fee recipient"},
		{"all with two addresses", Delta{AllValidators: true, FeeRecipients: []string{addrB, addrC}}, "all validators takes a single fee recipient"},
		{"all with invalid address", Delta{AllValidators: true, FeeRecipients: []string{"0x123"}}, "validate address"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Apply(lock, c, test.delta)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
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
		{FeeRecipientValidators: []string{pubkeyHex(lock.Validators[1].PubKey)}, FeeRecipients: []string{addrB}},
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

func TestApplyInvalidBuilderDelta(t *testing.T) {
	lock := testLock(t, 2)
	c, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	_, err = Apply(lock, c, Delta{BuilderURLs: []string{}})
	require.ErrorContains(t, err, "builder urls must not be empty")

	_, err = Apply(lock, c, Delta{NoBuilders: true, BuilderMinBid: new(uint64(5))})
	require.ErrorContains(t, err, "no builders excludes")
}

func TestApplyDuplicateBuilderURLs(t *testing.T) {
	lock := testLock(t, 1)
	c, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	_, err = Apply(lock, c, Delta{BuilderURLs: []string{"https://a.example", "https://a.example"}})
	require.ErrorContains(t, err, "builder-urls entry is duplicated")
}
