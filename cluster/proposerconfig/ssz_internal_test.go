// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"testing"

	dynssz "github.com/pk910/dynamic-ssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
)

// The SSZ types of hashDocument, hashed by dynamic-ssz's reflection as other implementations would hash them.
type (
	sszDocument struct {
		Version        []byte `ssz-max:"16"`
		LockHash       [32]byte
		Revision       uint64
		DefaultConfig  sszSettings
		ProposerConfig []sszEntry `ssz-max:"65536"`
	}
	sszSettings struct {
		FeeRecipient []byte `ssz-max:"20"`
		GasLimit     uint64
		Builder      []sszBuilder `ssz-max:"1"`
	}
	sszBuilder struct {
		MinBid              uint64
		BuilderBoostFactor  uint64
		MaxExecutionPayment uint64
		Builders            [][]byte `ssz-max:"32,2048"`
	}
	sszEntry struct {
		Pubkey       [48]byte
		FeeRecipient [20]byte
	}
)

func toSSZ(t *testing.T, d Document) sszDocument {
	t.Helper()

	parse := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		require.NoError(t, err)

		return v
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		require.NoError(t, err)

		return b
	}

	res := sszDocument{
		Version:  []byte(d.Version),
		LockHash: [32]byte(d.LockHash),
		Revision: d.Revision,
		DefaultConfig: sszSettings{
			GasLimit: parse(d.Config.DefaultConfig.GasLimit),
		},
	}

	if d.Config.DefaultConfig.FeeRecipient != "" {
		res.DefaultConfig.FeeRecipient = decode(d.Config.DefaultConfig.FeeRecipient)
	}

	if b := d.Config.DefaultConfig.Builder; b != nil {
		builder := sszBuilder{MinBid: parse(b.MinBid), BuilderBoostFactor: parse(b.BuilderBoostFactor), MaxExecutionPayment: parse(b.MaxExecutionPayment)}
		for _, e := range b.Builders {
			builder.Builders = append(builder.Builders, []byte(e.URL))
		}

		res.DefaultConfig.Builder = []sszBuilder{builder}
	}

	for key, s := range d.Config.ProposerConfig {
		res.ProposerConfig = append(res.ProposerConfig, sszEntry{Pubkey: [48]byte(decode(key)), FeeRecipient: [20]byte(decode(s.FeeRecipient))})
	}

	slices.SortFunc(res.ProposerConfig, func(a, b sszEntry) int { return bytes.Compare(a.Pubkey[:], b.Pubkey[:]) })

	return res
}

func TestHashMatchesReflectiveSSZ(t *testing.T) {
	lock := testLock(t, 4)
	builder := &Builder{
		MinBid: "1", BuilderBoostFactor: "90", MaxExecutionPayment: "2",
		Builders: []BuilderEntry{{URL: "https://b1.example"}, {URL: "https://b2.example/?a=1&b=2"}},
	}

	diverging, err := NewConfig(lock, []string{addrA, addrB, addrA, "0x000000000000000000000000000000000000000c"}, DefaultGasLimit, builder)
	require.NoError(t, err)
	require.Len(t, diverging.ProposerConfig, 2)

	uniform, err := NewConfig(lock, []string{addrA, addrA, addrA, addrA}, 60_000_000, nil)
	require.NoError(t, err)

	noFee, err := NewConfig(lock, []string{"", "", "", ""}, DefaultGasLimit, &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0"})
	require.NoError(t, err)

	for name, cfg := range map[string]Config{"diverging": diverging, "uniform": uniform, "no fee recipient": noFee} {
		t.Run(name, func(t *testing.T) {
			doc := Document{Version: Version, LockHash: lock.LockHash, Revision: 3, Config: cfg}

			want, err := dynssz.GetGlobalDynSsz().HashTreeRoot(toSSZ(t, doc))
			require.NoError(t, err)

			got, err := doc.Hash()
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestHashRejects(t *testing.T) {
	lock := testLock(t, 1)
	v0 := pubkeyHex(lock.Validators[0].PubKey)

	tests := []struct {
		name   string
		modify func(*Config)
		errMsg string
	}{
		{"entry gas limit", func(c *Config) { c.ProposerConfig[v0] = Settings{FeeRecipient: addrB, GasLimit: "1"} }, "entry sets more than fee_recipient"},
		{"entry builder", func(c *Config) { c.ProposerConfig[v0] = Settings{FeeRecipient: addrB, Builder: &Builder{}} }, "entry sets more than fee_recipient"},
		{"entry without fee recipient", func(c *Config) { c.ProposerConfig[v0] = Settings{} }, "invalid 0x hex"},
		{"short pubkey", func(c *Config) { c.ProposerConfig["0xabcd"] = Settings{FeeRecipient: addrB} }, "invalid 0x hex"},
		{"unprefixed fee recipient", func(c *Config) { c.DefaultConfig.FeeRecipient = addrA[2:] }, "invalid 0x hex"},
		{"leading zero", func(c *Config) { c.DefaultConfig.GasLimit = "060000000" }, "not a canonical decimal number"},
		{"empty gas limit", func(c *Config) { c.DefaultConfig.GasLimit = "" }, "not a canonical decimal number"},
		{"builder override", func(c *Config) { c.DefaultConfig.Builder.Builders[0].MinBid = "5" }, "builder entry sets more than url"},
		{"long url", func(c *Config) {
			c.DefaultConfig.Builder.Builders[0].URL = "https://" + strings.Repeat("a", core.MaxBuilderURLSize)
		}, "incorrect list size"},
		{"too many builders", func(c *Config) {
			for i := range sszMaxBuilders {
				c.DefaultConfig.Builder.Builders = append(c.DefaultConfig.Builder.Builders, BuilderEntry{URL: "https://b" + strconv.Itoa(i) + ".example"})
			}
		}, "incorrect list size"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, testBuilder())
			require.NoError(t, err)

			tt.modify(&cfg)

			_, err = Document{Version: Version, LockHash: lock.LockHash, Config: cfg}.Hash()
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}
