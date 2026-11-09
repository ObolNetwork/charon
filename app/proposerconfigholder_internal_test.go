// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
)

// startHolder returns a holder of the signed revision 1 document at the fixture path, running until test end.
// The returned stop func ends the holder, after which the fixture logs are safe to read.
func startHolder(t *testing.T, f pcFixture) (*proposerConfigHolder, proposerconfig.Document, func()) {
	t.Helper()

	doc := f.doc(t, 1, 60_000_000, nil, 0, 1, 2)
	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))

	h, err := newProposerConfigHolder(doc, f.lock, f.nodeIdx, f.path)
	require.NoError(t, err)

	// The gauges are package-global, start from the loaded document's state.
	setProposerConfigGauges(doc, true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = h.Run(ctx)
	}()

	var once sync.Once

	stop := func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	t.Cleanup(stop)

	// Give the watcher time to register before files change.
	time.Sleep(100 * time.Millisecond)

	return h, doc, stop
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()

	require.Eventually(t, cond, 5*time.Second, 10*time.Millisecond)
}

func TestHolderReloadOnRename(t *testing.T) {
	f := newPCFixture(t)
	h, _, stop := startHolder(t, f)

	// Archives and temp files next to the file do not trigger a reload.
	dir := filepath.Dir(f.path)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proposer-config-revision-1.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proposer-config.json.123.tmp"), []byte("{}"), 0o644))
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, 0, h.reloads.Load())
	require.EqualValues(t, 1, h.Document().Revision)

	next := f.doc(t, 2, 70_000_000, nil, 0, 1, 2)
	require.NoError(t, proposerconfig.Write(f.path, next, f.lock, f.nodeIdx))

	eventually(t, func() bool { return h.Document().Revision == 2 })
	require.EqualValues(t, 70_000_000, h.GasLimit())

	hash, err := next.Hash()
	require.NoError(t, err)
	require.Equal(t, hash[:], h.Hash())
	require.InDelta(t, 2, testutil.ToFloat64(proposerConfigRevisionGauge), 0)
	stop()
	require.Contains(t, f.logs.String(), "Proposer config reloaded")
}

func TestHolderIdenticalReloadIsNoop(t *testing.T) {
	f := newPCFixture(t)
	h, doc, stop := startHolder(t, f)

	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))
	eventually(t, func() bool { return h.reloads.Load() > 0 })
	stop()
	require.NotContains(t, f.logs.String(), "Proposer config reloaded")
}

func invalidGauge() float64 { return testutil.ToFloat64(proposerConfigInvalidGauge) }

func TestHolderRejectsLowerRevision(t *testing.T) {
	f := newPCFixture(t)
	h, _, stop := startHolder(t, f)

	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return h.Document().Revision == 2 })

	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 1, 60_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 2, h.Document().Revision)
	require.InDelta(t, 2, testutil.ToFloat64(proposerConfigRevisionGauge), 0)

	stop()
	require.Contains(t, f.logs.String(), "lower revision")
}

func TestHolderRejectsInvalid(t *testing.T) {
	f := newPCFixture(t)
	h, _, stop := startHolder(t, f)

	require.InDelta(t, 0, invalidGauge(), 0)

	// A document with fewer signatures than the threshold fails verification.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 70_000_000, nil, 0), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 1, h.Document().Revision)

	// A valid higher revision recovers.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 3, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return h.Document().Revision == 3 })
	eventually(t, func() bool { return invalidGauge() == 0 })

	// A file whose stored hash mismatches its content.
	b, err := os.ReadFile(f.path)
	require.NoError(t, err)

	corrupt := strings.Replace(string(b), `"revision_hash": "0x`, `"revision_hash": "0xff`, 1)
	require.NoError(t, os.WriteFile(f.path+".tmp", []byte(corrupt), 0o644))
	require.NoError(t, os.Rename(f.path+".tmp", f.path))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 3, h.Document().Revision)

	stop()
	require.Contains(t, f.logs.String(), "keeping revision 3")
}

func TestHolderGetters(t *testing.T) {
	f := newPCFixture(t)

	seed := proposerconfig.Seed{
		GasLimit:                   proposerconfig.DefaultGasLimit,
		BuilderURLs:                []string{"https://Relay-A.example.com:443/path", "http://relay-b.example.com"},
		BuilderMinBid:              7,
		BuilderBoostFactor:         120,
		BuilderMaxExecutionPayment: 3,
	}

	doc, err := ProposerConfigGenesis(f.lock, seed, func(core.PubKey) string { return "" })
	require.NoError(t, err)

	h, err := newProposerConfigHolder(doc, f.lock, f.nodeIdx, f.path)
	require.NoError(t, err)

	// Each builder is an entry without its auth: the fetcher adds the aggregated auth per proposal.
	cfg := h.BuilderConfig()
	require.EqualValues(t, 7, cfg.MinBid)
	require.EqualValues(t, 120, cfg.BuilderBoostFactor)
	require.Len(t, cfg.Builders, 2)

	for i, entry := range cfg.Builders {
		require.Equal(t, []byte(seed.BuilderURLs[i]), entry.URL)
		require.Nil(t, entry.Auth)
		require.Empty(t, entry.BuilderPubkeys)
		require.EqualValues(t, 3, entry.MaxExecutionPayment)
		require.EqualValues(t, 7, entry.MinBid)
		require.EqualValues(t, 120, entry.BuilderBoostFactor)
	}

	require.Equal(t, []string{"relay-a.example.com", "relay-b.example.com"}, h.BuilderHosts())

	require.Equal(t, proposerconfig.DefaultGasLimit, h.GasLimit())
	require.Equal(t, doc, h.Document())
	require.Equal(t, 2, testutil.CollectAndCount(builderURLGauge))

	pubkey, err := core.PubKeyFromBytes(f.lock.Validators[0].PubKey)
	require.NoError(t, err)
	require.Equal(t, f.lock.FeeRecipientAddresses()[0], h.FeeRecipient(pubkey))

	// No builder block.
	doc, err = ProposerConfigGenesis(f.lock, proposerconfig.Seed{GasLimit: 1}, func(core.PubKey) string { return "" })
	require.NoError(t, err)

	h, err = newProposerConfigHolder(doc, f.lock, f.nodeIdx, f.path)
	require.NoError(t, err)
	require.Equal(t, &gloas.BuilderConfig{BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor, Builders: []*gloas.BuilderEntry{}}, h.BuilderConfig())
	require.Empty(t, h.BuilderHosts())
	require.Zero(t, testutil.CollectAndCount(builderURLGauge))
}
