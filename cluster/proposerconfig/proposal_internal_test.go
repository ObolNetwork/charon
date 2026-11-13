// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProposalFileRoundTrip(t *testing.T) {
	lock := testLock(t, 3)
	cfg, err := NewConfig(lock, []string{addrA, addrA, addrB}, 60_000_000, testBuilder())
	require.NoError(t, err)

	doc := Document{Version: Version, LockHash: lock.LockHash, Revision: 3, Config: cfg}

	b, err := MarshalProposal(doc)
	require.NoError(t, err)

	got, err := ParseProposal(b)
	require.NoError(t, err)
	require.Equal(t, doc.LockHash, got.LockHash)
	require.Equal(t, doc.Revision, got.Revision)

	same, err := SameConfig(cfg, got.Config)
	require.NoError(t, err)
	require.True(t, same)

	// The seed and the proposal are one file format: a seed is a proposal without the cluster's own values.
	_, err = ParseSeed(b)
	require.ErrorContains(t, err, "lock_hash")
}

func TestParseProposal(t *testing.T) {
	const lockHash = `"lock_hash":"0x0102"`

	tests := []struct {
		name        string
		json        string
		errContains string
	}{
		{name: "missing lock hash", json: `{"version":"v1.0.0","revision":1,"default_config":{"gas_limit":"1"}}`, errContains: "lock_hash"},
		{name: "bad lock hash", json: `{"version":"v1.0.0","lock_hash":"zz","revision":1,"default_config":{"gas_limit":"1"}}`, errContains: "lock_hash"},
		{name: "missing revision", json: `{"version":"v1.0.0",` + lockHash + `,"default_config":{"gas_limit":"1"}}`, errContains: "revision"},
		{name: "other major", json: `{"version":"v2.0.0",` + lockHash + `,"revision":1,"default_config":{"gas_limit":"1"}}`, errContains: "version"},
		{name: "unknown field", json: `{"version":"v1.0.0",` + lockHash + `,"revision":1,"signatures":[],"default_config":{"gas_limit":"1"}}`, errContains: "signatures"},
		{name: "trailing data", json: `{"version":"v1.0.0",` + lockHash + `,"revision":1,"default_config":{"gas_limit":"1"}}{}`, errContains: "trailing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProposal([]byte(tt.json))
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestApplyProposal(t *testing.T) {
	lock := testLock(t, 3)
	base, err := NewConfig(lock, []string{addrA, addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)

	v2 := pubkeyHex(lock.Validators[2].PubKey)

	t.Run("equals the delta result", func(t *testing.T) {
		want, err := Apply(lock, base, Delta{GasLimit: 60_000_000, BuilderURLs: []string{"https://a.example"}})
		require.NoError(t, err)

		got, err := ApplyProposal(lock, base, want)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("canonicalises", func(t *testing.T) {
		// Checksummed addresses and an entry repeating the default.
		proposal := Config{
			DefaultConfig: Settings{FeeRecipient: "0x" + strings.ToUpper(addrC[2:]), GasLimit: "60000000"},
			ProposerConfig: map[string]Settings{
				v2:                                   {FeeRecipient: "0x" + strings.ToUpper(addrB[2:])},
				pubkeyHex(lock.Validators[0].PubKey): {FeeRecipient: addrC},
			},
		}

		want, err := NewConfig(lock, []string{addrC, addrC, addrB}, 60_000_000, nil)
		require.NoError(t, err)

		got, err := ApplyProposal(lock, base, proposal)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("default as written", func(t *testing.T) {
		// The file's default is kept even if most validators have their own fee recipient.
		proposal := Config{
			DefaultConfig: Settings{FeeRecipient: addrA, GasLimit: "200000000"},
			ProposerConfig: map[string]Settings{
				pubkeyHex(lock.Validators[1].PubKey): {FeeRecipient: addrB},
				v2:                                   {FeeRecipient: addrB},
			},
		}

		got, err := ApplyProposal(lock, base, proposal)
		require.NoError(t, err)
		require.Equal(t, proposal.DefaultConfig, got.DefaultConfig)
		require.Equal(t, proposal.ProposerConfig, got.ProposerConfig)
	})

	t.Run("zero fee recipient kept", func(t *testing.T) {
		// A testnet cluster created with the zero address keeps it through other changes.
		zero, err := NewConfig(lock, []string{zeroAddress, zeroAddress, zeroAddress}, DefaultGasLimit, nil)
		require.NoError(t, err)

		want, err := Apply(lock, zero, Delta{GasLimit: 60_000_000})
		require.NoError(t, err)

		got, err := ApplyProposal(lock, zero, want)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("no change", func(t *testing.T) {
		_, err := ApplyProposal(lock, base, base)
		require.ErrorIs(t, err, ErrNoChange)
	})

	withDefault := func(s Settings) Config {
		c := Config{DefaultConfig: base.DefaultConfig, ProposerConfig: base.ProposerConfig}
		if s.GasLimit != "" {
			c.DefaultConfig.GasLimit = s.GasLimit
		}

		c.DefaultConfig.Builder = s.Builder

		return c
	}

	tests := []struct {
		name        string
		proposal    Config
		errContains string
	}{
		{"uppercase validator key", Config{DefaultConfig: base.DefaultConfig, ProposerConfig: map[string]Settings{"0x" + strings.ToUpper(v2[2:]): {FeeRecipient: addrA}}}, "proposer_config key must be lowercase"},
		{"no fee recipient", Config{DefaultConfig: Settings{GasLimit: "60000000"}, ProposerConfig: base.ProposerConfig}, "fee recipient must not be removed"},
		{"zero fee recipient", Config{DefaultConfig: Settings{FeeRecipient: "0x0000000000000000000000000000000000000000", GasLimit: "60000000"}}, "zero fee recipient"},
		{"unknown validator", Config{DefaultConfig: base.DefaultConfig, ProposerConfig: map[string]Settings{"0xabcd": {FeeRecipient: addrA}}}, "not a lowercase lock validator pubkey"},
		{"per validator gas limit", Config{DefaultConfig: base.DefaultConfig, ProposerConfig: map[string]Settings{v2: {GasLimit: "1"}}}, "sets more than fee_recipient"},
		{"bad fee recipient", Config{DefaultConfig: Settings{FeeRecipient: "0x12", GasLimit: "1"}}, "default config"},
		{"zero gas limit", withDefault(Settings{GasLimit: "0"}), "gas_limit must be greater than 0"},
		{"empty builders", withDefault(Settings{Builder: &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0"}}), "builders must not be empty"},
		{"zero boost factor", withDefault(Settings{Builder: &Builder{MinBid: "0", BuilderBoostFactor: "0", MaxExecutionPayment: "0", Builders: []BuilderEntry{{URL: "https://a.example"}}}}), "builder_boost_factor must be greater than 0"},
		{"bad builder url", withDefault(Settings{Builder: &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []BuilderEntry{{URL: "ftp://a.example"}}}}), "default_config.builder.builders entry is not a valid http(s) URL"},
		{"builder entry override", withDefault(Settings{Builder: &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: []BuilderEntry{{URL: "https://a.example", MinBid: "1"}}}}), "sets more than url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyProposal(lock, base, tt.proposal)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestWriteNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "file.json")
	require.NoError(t, WriteNewFile(path, []byte("a")))

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "a", string(b))

	require.ErrorIs(t, WriteNewFile(path, []byte("b")), os.ErrExist)
}
