// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
)

const editCmd = "charon alpha edit proposer-config"

// pcFixture is a 3 of 4 cluster with 3 validators, loaded as node 2.
type pcFixture struct {
	lock    cluster.Lock
	keys    []*k1.PrivateKey
	conf    Config
	nodeIdx cluster.NodeIdx
	path    string
	logs    *zaptest.Buffer
}

func newPCFixture(t *testing.T) pcFixture {
	t.Helper()

	lock, keys, _ := cluster.NewForT(t, 3, 3, 4, 0, rand.New(rand.NewSource(0)))
	path := filepath.Join(t.TempDir(), "vc-config", "proposer-config.json")

	logs := new(zaptest.Buffer)
	log.InitLogfmtForT(t, logs)

	return pcFixture{
		lock: lock,
		keys: keys,
		conf: Config{
			ProposerConfigFile: path,
			ProposerConfigSeed: proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit, BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor},
		},
		nodeIdx: cluster.NodeIdx{PeerIdx: 2, ShareIdx: 3},
		path:    path,
		logs:    logs,
	}
}

func (f pcFixture) load(t *testing.T, gloasActive bool) (proposerconfig.Document, error) {
	t.Helper()

	noOverrides := func(core.PubKey) string { return "" }

	return loadProposerConfig(context.Background(), f.conf, f.lock, f.nodeIdx, noOverrides, func() bool { return gloasActive })
}

// loadBadInitial loads with an override fee recipient that fails deriving the initial config.
func (f pcFixture) loadBadInitial(t *testing.T) (proposerconfig.Document, error) {
	t.Helper()

	badOverride := func(core.PubKey) string { return "0xnot-an-address" }

	return loadProposerConfig(context.Background(), f.conf, f.lock, f.nodeIdx, badOverride, func() bool { return false })
}

// doc returns a document with the lock's fee recipients, the given gas limit and builder, signed by signers.
func (f pcFixture) doc(t *testing.T, revision uint64, gasLimit uint64, builder *proposerconfig.Builder, signers ...int) proposerconfig.Document {
	t.Helper()

	cfg, err := proposerconfig.NewConfig(f.lock, f.lock.FeeRecipientAddresses(), gasLimit, builder)
	require.NoError(t, err)

	doc := proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: f.lock.LockHash,
		Revision: revision,
		Config:   cfg,
	}

	for _, idx := range signers {
		sig, err := proposerconfig.Sign(doc, f.keys[idx])
		require.NoError(t, err)

		doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: idx, Signature: sig})
	}

	return doc
}

func (f pcFixture) write(t *testing.T, doc proposerconfig.Document) []byte {
	t.Helper()

	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))

	b, err := os.ReadFile(f.path)
	require.NoError(t, err)

	return b
}

func requireGauges(t *testing.T, revision, invalid float64) {
	t.Helper()

	require.InDelta(t, revision, promtestutil.ToFloat64(proposerConfigRevisionGauge), 0)
	require.InDelta(t, invalid, promtestutil.ToFloat64(proposerConfigInvalidGauge), 0)
}

func requireFile(t *testing.T, path string, want []byte) {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(b))
}

func TestLoadInitialProposerConfig(t *testing.T) {
	f := newPCFixture(t)
	require.EqualValues(t, 30_000_000, f.lock.TargetGasLimit)

	overridePubkey, err := core.PubKeyFromBytes(f.lock.Validators[0].PubKey)
	require.NoError(t, err)

	const overrideAddr = "0xcccccccccccccccccccccccccccccccccccccccc"

	feeRecipientFunc := func(pubkey core.PubKey) string {
		if pubkey == overridePubkey {
			return overrideAddr
		}

		return "" // Falls back to the lock.
	}

	doc, err := loadProposerConfig(context.Background(), f.conf, f.lock, f.nodeIdx, feeRecipientFunc, func() bool { return false })
	require.NoError(t, err)

	lockFees := f.lock.FeeRecipientAddresses()
	wantFees := []string{overrideAddr, strings.ToLower(lockFees[1]), strings.ToLower(lockFees[2])}

	require.Equal(t, proposerconfig.Version, doc.Version)
	require.Equal(t, f.lock.LockHash, doc.LockHash)
	require.Zero(t, doc.Revision)
	require.Empty(t, doc.Signatures)
	require.Equal(t, "200000000", doc.Config.DefaultConfig.GasLimit)
	require.Nil(t, doc.Config.DefaultConfig.Builder)
	require.Equal(t, wantFees, doc.Config.FeeRecipients(f.lock))

	loaded, err := proposerconfig.Load(f.path, f.lock, f.nodeIdx)
	require.NoError(t, err)
	require.Equal(t, doc.Config, loaded.Config)
	require.NoError(t, proposerconfig.Verify(loaded, f.lock))

	requireGauges(t, 0, 0)
	require.NotContains(t, f.logs.String(), editCmd)

	t.Run("post gloas warns unsigned", func(t *testing.T) {
		require.NoError(t, os.Remove(f.path))
		f.logs.Reset()

		_, err := f.load(t, true)
		require.NoError(t, err)
		require.Contains(t, f.logs.String(), editCmd)
	})
}

func TestLoadProposerConfigRevision0Drift(t *testing.T) {
	f := newPCFixture(t)
	f.conf.ProposerConfigSeed.BuilderURLs = []string{"https://a.example.com"}

	fileBuilder := proposerconfig.Seed{BuilderURLs: []string{"https://b.example.com"}, BuilderBoostFactor: 100}.Builder()
	want := f.doc(t, 0, proposerconfig.DefaultGasLimit, fileBuilder)
	written := f.write(t, want)

	doc, err := f.load(t, false)
	require.NoError(t, err)
	require.Equal(t, want.Config, doc.Config)
	requireFile(t, f.path, written)

	logs := f.logs.String()
	require.Contains(t, logs, editCmd)
	require.Contains(t, logs, "default.builder.urls")
	require.NotContains(t, logs, "default.gas_limit")
	requireGauges(t, 0, 0)

	t.Run("many differences log one warning", func(t *testing.T) {
		fees := []string{
			"0x00000000000000000000000000000000000000c1",
			"0x00000000000000000000000000000000000000c2",
			"0x00000000000000000000000000000000000000c3",
		}
		cfg, err := proposerconfig.NewConfig(f.lock, fees, proposerconfig.DefaultGasLimit, fileBuilder)
		require.NoError(t, err)
		f.write(t, proposerconfig.Document{Version: proposerconfig.Version, LockHash: f.lock.LockHash, Config: cfg})
		f.logs.Reset()

		_, err = f.load(t, false)
		require.NoError(t, err)

		logs := f.logs.String()
		require.Equal(t, 1, strings.Count(logs, "level=warn"), logs)
		require.Contains(t, logs, "differences=4")
		require.Contains(t, logs, "default.builder.urls")
	})
}

func TestLoadProposerConfigSigned(t *testing.T) {
	f := newPCFixture(t)
	f.conf.ProposerConfigSeed.BuilderURLs = []string{"https://a.example.com"}
	f.conf.ProposerConfigSeed.BuilderMinBid = 0 // Set to its default, equal to nothing in a signed file without builders.
	f.conf.ProposerConfigSeed.NonDefault = []string{"proposer-config-builder-urls", "proposer-config-builder-min-bid"}

	want := f.doc(t, 1, 60_000_000, nil, 0, 1, 3)
	written := f.write(t, want)

	doc, err := f.load(t, true)
	require.NoError(t, err)
	require.Equal(t, want.Config, doc.Config)
	require.EqualValues(t, 1, doc.Revision)
	require.Equal(t, []int{0, 1, 3}, doc.SignerIndexes())
	requireFile(t, f.path, written)

	// Only explicitly set flags are compared: the default gas limit differs from the file but is not reported.
	logs := f.logs.String()
	require.Equal(t, 1, strings.Count(logs, "level=warn"), logs)
	require.Contains(t, logs, `flags="proposer-config-builder-urls: file none, flag https://a.example.com; proposer-config-builder-min-bid: file none, flag 0"`)
	require.NotContains(t, logs, "proposer-config-gas-limit")
	require.Contains(t, logs, editCmd)
	require.NotContains(t, logs, "level=error")
	requireGauges(t, 1, 0)

	t.Run("explicit gas limit differing warns", func(t *testing.T) {
		f.conf.ProposerConfigSeed.BuilderURLs = nil
		f.conf.ProposerConfigSeed.NonDefault = []string{"proposer-config-gas-limit"}
		f.logs.Reset()

		_, err := f.load(t, true)
		require.NoError(t, err)
		require.Contains(t, f.logs.String(), `flags="proposer-config-gas-limit: file 60000000, flag 200000000"`)
	})

	t.Run("flags left at their defaults do not warn", func(t *testing.T) {
		f.conf.ProposerConfigSeed.BuilderURLs = nil
		f.conf.ProposerConfigSeed.GasLimit = proposerconfig.DefaultGasLimit
		f.conf.ProposerConfigSeed.NonDefault = nil
		f.logs.Reset()

		_, err := f.load(t, true)
		require.NoError(t, err)
		require.NotContains(t, f.logs.String(), "level=warn")
	})

	t.Run("matching flags do not warn", func(t *testing.T) {
		f.conf.ProposerConfigSeed.BuilderURLs = nil
		f.conf.ProposerConfigSeed.GasLimit = 60_000_000
		f.conf.ProposerConfigSeed.NonDefault = []string{"proposer-config-gas-limit"}
		f.logs.Reset()

		_, err := f.load(t, true)
		require.NoError(t, err)
		require.NotContains(t, f.logs.String(), "level=warn")
	})
}

func TestLoadProposerConfigInvalidSigned(t *testing.T) {
	f := newPCFixture(t)

	want := f.doc(t, 1, proposerconfig.DefaultGasLimit, nil, 0, 1) // Below threshold 3.
	written := f.write(t, want)

	doc, err := f.load(t, false)
	require.NoError(t, err)
	require.Equal(t, want.Config, doc.Config)
	require.EqualValues(t, 1, doc.Revision)
	require.Contains(t, f.logs.String(), "level=error")
	requireFile(t, f.path, written)
	requireGauges(t, 1, 1)
}

func TestLoadProposerConfigWrongLock(t *testing.T) {
	t.Run("lock hash only", func(t *testing.T) {
		f := newPCFixture(t)

		other := f.doc(t, 0, proposerconfig.DefaultGasLimit, nil)
		other.LockHash = bytes.Repeat([]byte{0x01}, 32)
		written := f.write(t, other)

		_, err := f.load(t, false)
		require.ErrorIs(t, err, proposerconfig.ErrLockHashMismatch)
		require.ErrorContains(t, err, "after a lock-changing edit, use vc-config/ from its output directory")
		requireFile(t, f.path, written)
	})

	t.Run("other cluster's file", func(t *testing.T) {
		f := newPCFixture(t)
		otherLock, _, _ := cluster.NewForT(t, 3, 3, 4, 1, rand.New(rand.NewSource(1)))

		// Diverging fee recipients give entries keyed by the other cluster's pubshares.
		cfg, err := proposerconfig.NewConfig(otherLock, otherLock.FeeRecipientAddresses(), proposerconfig.DefaultGasLimit, nil)
		require.NoError(t, err)
		require.NotEmpty(t, cfg.ProposerConfig)

		doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: otherLock.LockHash, Config: cfg}
		require.NoError(t, proposerconfig.Write(f.path, doc, otherLock, f.nodeIdx))

		before, err := os.ReadFile(f.path)
		require.NoError(t, err)

		_, err = f.load(t, false)
		require.ErrorIs(t, err, proposerconfig.ErrLockHashMismatch)
		requireFile(t, f.path, before)
	})
}

func TestLoadInitialProposerConfigFailure(t *testing.T) {
	t.Run("valid signed file never derives the initial config", func(t *testing.T) {
		f := newPCFixture(t)
		want := f.doc(t, 1, proposerconfig.DefaultGasLimit, nil, 0, 1, 2)
		f.write(t, want)

		doc, err := f.loadBadInitial(t)
		require.NoError(t, err)
		require.Equal(t, want.Config, doc.Config)
		requireGauges(t, 1, 0)
	})

	t.Run("revision 0 file skips the drift check", func(t *testing.T) {
		f := newPCFixture(t)
		want := f.doc(t, 0, proposerconfig.DefaultGasLimit, nil)
		f.write(t, want)

		doc, err := f.loadBadInitial(t)
		require.NoError(t, err)
		require.Equal(t, want.Config, doc.Config)
		require.Contains(t, f.logs.String(), "level=warn")
		requireGauges(t, 0, 0)
	})

	t.Run("no file", func(t *testing.T) {
		f := newPCFixture(t)

		_, err := f.loadBadInitial(t)
		require.Error(t, err)

		_, err = os.Stat(f.path)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("unloadable file", func(t *testing.T) {
		f := newPCFixture(t)
		require.NoError(t, os.MkdirAll(filepath.Dir(f.path), 0o755))
		require.NoError(t, os.WriteFile(f.path, []byte("{"), 0o644))

		_, err := f.loadBadInitial(t)
		require.Error(t, err)
	})
}

func TestLoadProposerConfigWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	f := newPCFixture(t)
	dir := filepath.Dir(f.path)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	doc, err := f.load(t, false)
	require.NoError(t, err)
	require.Zero(t, doc.Revision)
	require.Equal(t, "200000000", doc.Config.DefaultConfig.GasLimit)
	require.Contains(t, f.logs.String(), "level=error")
	requireGauges(t, 0, 1)
}

func TestLoadProposerConfigUndecodable(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, f pcFixture)
	}{
		{
			name: "corrupt json",
			setup: func(t *testing.T, f pcFixture) {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Dir(f.path), 0o755))
				require.NoError(t, os.WriteFile(f.path, []byte(`{"version": "v1.0.0", `), 0o644))
			},
		},
		{
			name: "integer version",
			setup: func(t *testing.T, f pcFixture) {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Dir(f.path), 0o755))
				require.NoError(t, os.WriteFile(f.path, []byte(`{"version": 1, "proposer_config": {}, "default_config": {"gas_limit": "30000000"}}`), 0o644))
			},
		},
		{
			name: "other node's pubshares",
			setup: func(t *testing.T, f pcFixture) {
				t.Helper()

				doc := f.doc(t, 0, proposerconfig.DefaultGasLimit, nil)
				require.NotEmpty(t, doc.Config.ProposerConfig)
				require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPCFixture(t)
			f.conf.ProposerConfigSeed.GasLimit = 60_000_000
			test.setup(t, f)

			before, err := os.ReadFile(f.path)
			require.NoError(t, err)

			doc, err := f.load(t, false)
			require.NoError(t, err)
			require.Zero(t, doc.Revision)
			require.Empty(t, doc.Signatures)
			require.Equal(t, "60000000", doc.Config.DefaultConfig.GasLimit)
			require.Contains(t, f.logs.String(), "level=error")
			require.Contains(t, f.logs.String(), "delete it to regenerate")
			requireFile(t, f.path, before)
			requireGauges(t, 0, 1)
		})
	}

	t.Run("path is a directory", func(t *testing.T) {
		f := newPCFixture(t)
		require.NoError(t, os.MkdirAll(f.path, 0o755))

		doc, err := f.load(t, false)
		require.NoError(t, err)
		require.Zero(t, doc.Revision)
		require.Contains(t, f.logs.String(), "level=error")

		info, err := os.Stat(f.path)
		require.NoError(t, err)
		require.True(t, info.IsDir())
		requireGauges(t, 0, 1)
	})
}

func TestLoadProposerConfigLockWithoutFeeRecipients(t *testing.T) {
	f := newPCFixture(t)

	// v1.0 and v1.1 locks may have no fee recipients.
	f.lock.ValidatorAddresses = slices.Clone(f.lock.ValidatorAddresses)
	for i := range f.lock.ValidatorAddresses {
		f.lock.ValidatorAddresses[i].FeeRecipientAddress = ""
	}

	doc, err := f.load(t, false)
	require.NoError(t, err)
	require.Empty(t, doc.Config.DefaultConfig.FeeRecipient)
	require.Empty(t, doc.Config.ProposerConfig)
	requireGauges(t, 0, 0)

	loaded, err := proposerconfig.Load(f.path, f.lock, f.nodeIdx)
	require.NoError(t, err)
	require.NoError(t, proposerconfig.Verify(loaded, f.lock))
}

func TestLoadProposerConfigTestLock(t *testing.T) {
	f := newPCFixture(t)
	f.conf.TestConfig.Lock = &f.lock

	doc, err := f.load(t, false)
	require.NoError(t, err)
	require.Zero(t, doc.Revision)
	require.Equal(t, "200000000", doc.Config.DefaultConfig.GasLimit)

	_, err = os.Stat(f.path)
	require.ErrorIs(t, err, os.ErrNotExist)
}
