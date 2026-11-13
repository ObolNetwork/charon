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

// startService returns a service of the signed revision 1 document at the fixture path, running until test end.
// The returned stop func ends the service, after which the fixture logs are safe to read.
func startService(t *testing.T, f pcFixture) (*proposerConfigService, proposerconfig.Document, func()) {
	t.Helper()

	doc := f.doc(t, 1, 60_000_000, nil, 0, 1, 2)
	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))

	// The service watches the file from its construction, so Run only drains the changes.
	s, err := f.service(t, false)
	require.NoError(t, err)
	require.NotNil(t, s.changes)

	return s, doc, runService(t, f, s)
}

// runService runs the service until the returned stop func is called, which waits for it to return, so that the
// fixture logs are safe to read after and no reload outlives the test.
func runService(t *testing.T, f pcFixture, s *proposerConfigService) func() {
	t.Helper()

	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = s.Run(ctx)
	}()

	var once sync.Once

	stop := func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	t.Cleanup(stop)

	return stop
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()

	require.Eventually(t, cond, 5*time.Second, 10*time.Millisecond)
}

func TestProposerConfigServiceReloadOnRename(t *testing.T) {
	f := newPCFixture(t)
	s, _, stop := startService(t, f)

	// Archives and temp files next to the file do not trigger a reload.
	dir := filepath.Dir(f.path)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proposer-config-revision-1.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proposer-config.json.123.tmp"), []byte("{}"), 0o644))
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, 0, s.reloads.Load())
	require.EqualValues(t, 1, s.Document().Revision)

	next := f.doc(t, 2, 70_000_000, nil, 0, 1, 2)
	require.NoError(t, proposerconfig.Write(f.path, next, f.lock, f.nodeIdx))

	eventually(t, func() bool { return s.Document().Revision == 2 })
	require.EqualValues(t, 70_000_000, s.GasLimit())

	hash, err := next.Hash()
	require.NoError(t, err)
	require.Equal(t, hash[:], s.Hash())
	require.InDelta(t, 2, testutil.ToFloat64(proposerConfigRevisionGauge), 0)
	stop()
	require.Contains(t, f.logs.String(), "Proposer config reloaded")
}

func TestProposerConfigServiceIdenticalReloadIsNoop(t *testing.T) {
	f := newPCFixture(t)
	s, doc, stop := startService(t, f)

	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))
	eventually(t, func() bool { return s.reloads.Load() > 0 })
	stop()
	require.NotContains(t, f.logs.String(), "Proposer config reloaded")
}

func invalidGauge() float64 { return testutil.ToFloat64(proposerConfigInvalidGauge) }

func TestProposerConfigServiceRejectsLowerRevision(t *testing.T) {
	f := newPCFixture(t)
	s, _, stop := startService(t, f)

	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return s.Document().Revision == 2 })

	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 1, 60_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 2, s.Document().Revision)
	require.InDelta(t, 2, testutil.ToFloat64(proposerConfigRevisionGauge), 0)

	stop()
	require.Contains(t, f.logs.String(), "lower revision")
}

func TestProposerConfigServiceRejectsSameRevisionOtherContent(t *testing.T) {
	f := newPCFixture(t)
	s, _, stop := startService(t, f)

	// Revision 1 signed by the threshold with another gas limit.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 1, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 60_000_000, s.GasLimit())

	// Revision 0 is unsigned, so hand edits of it are followed.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 0, 70_000_000, nil), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 }) // A lower revision is rejected too.
	require.EqualValues(t, 60_000_000, s.GasLimit())

	stop()
	require.Contains(t, f.logs.String(), "current revision with other content")
}

func TestProposerConfigServiceReplacesUnverified(t *testing.T) {
	f := newPCFixture(t)

	// Revision 2 with one signature fails verification but is served on start anyway.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 60_000_000, nil, 0), f.lock, f.nodeIdx))

	s, err := f.service(t, false)
	require.NoError(t, err)
	require.False(t, s.current.Load().verified)
	require.InDelta(t, 1, invalidGauge(), 0)

	runService(t, f, s)

	// A verified lower revision replaces it, the revision guards only protect a verified document.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 1, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return s.Document().Revision == 1 })
	require.True(t, s.current.Load().verified)
	require.InDelta(t, 0, invalidGauge(), 0)

	// From then on a lower revision is rejected.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 0, 60_000_000, nil), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 1, s.Document().Revision)
}

func TestProposerConfigServiceRepairedSignaturesReplaceUnverified(t *testing.T) {
	f := newPCFixture(t)

	doc := f.doc(t, 2, 60_000_000, nil, 0)
	require.NoError(t, proposerconfig.Write(f.path, doc, f.lock, f.nodeIdx))

	s, err := f.service(t, false)
	require.NoError(t, err)
	require.False(t, s.current.Load().verified)

	runService(t, f, s)

	// The same content with the threshold's signatures has the same hash, but replaces the unverified document.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 60_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return s.current.Load().verified })
	require.Len(t, s.Document().Signatures, 3)
	require.InDelta(t, 0, invalidGauge(), 0)
}

func TestProposerConfigServiceRejectsInvalid(t *testing.T) {
	f := newPCFixture(t)
	s, _, stop := startService(t, f)

	require.InDelta(t, 0, invalidGauge(), 0)

	// A document with fewer signatures than the threshold fails verification.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 2, 70_000_000, nil, 0), f.lock, f.nodeIdx))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 1, s.Document().Revision)

	// A valid higher revision recovers.
	require.NoError(t, proposerconfig.Write(f.path, f.doc(t, 3, 70_000_000, nil, 0, 1, 2), f.lock, f.nodeIdx))
	eventually(t, func() bool { return s.Document().Revision == 3 })
	eventually(t, func() bool { return invalidGauge() == 0 })

	// A file whose stored hash mismatches its config.
	b, err := os.ReadFile(f.path)
	require.NoError(t, err)

	corrupt := strings.Replace(string(b), `"revision_hash": "0x`, `"revision_hash": "0xff`, 1)
	require.NoError(t, os.WriteFile(f.path+".tmp", []byte(corrupt), 0o644))
	require.NoError(t, os.Rename(f.path+".tmp", f.path))
	eventually(t, func() bool { return invalidGauge() == 1 })
	require.EqualValues(t, 3, s.Document().Revision)

	stop()
	require.Contains(t, f.logs.String(), "keeping revision 3")
}

func TestProposerConfigServiceGetters(t *testing.T) {
	f := newPCFixture(t)
	f.conf.ProposerConfigSeed = proposerconfig.Seed{
		GasLimit:                   proposerconfig.DefaultGasLimit,
		BuilderURLs:                []string{"https://Relay-A.example.com:443/path", "http://relay-b.example.com"},
		BuilderMinBid:              7,
		BuilderBoostFactor:         120,
		BuilderMaxExecutionPayment: 3,
	}
	seed := f.conf.ProposerConfigSeed

	doc, err := InitialProposerConfig(f.lock, seed, func(core.PubKey) string { return "" })
	require.NoError(t, err)

	s, err := f.service(t, false)
	require.NoError(t, err)

	// Each builder is an entry without its auth: the fetcher adds the aggregated auth per proposal.
	cfg := s.BuilderConfig()
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

	require.Equal(t, []string{"relay-a.example.com", "relay-b.example.com"}, s.BuilderHosts())

	require.Equal(t, proposerconfig.DefaultGasLimit, s.GasLimit())
	require.Equal(t, doc, s.Document())
	require.Equal(t, 2, testutil.CollectAndCount(builderURLGauge))

	pubkey, err := core.PubKeyFromBytes(f.lock.Validators[0].PubKey)
	require.NoError(t, err)
	require.Equal(t, f.lock.FeeRecipientAddresses()[0], s.FeeRecipient(pubkey))

	// No builder block.
	f = newPCFixture(t)
	f.conf.ProposerConfigSeed = proposerconfig.Seed{GasLimit: 1}

	s, err = f.service(t, false)
	require.NoError(t, err)
	require.Equal(t, &gloas.BuilderConfig{BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor, Builders: []*gloas.BuilderEntry{}}, s.BuilderConfig())
	require.Empty(t, s.BuilderHosts())
	require.Zero(t, testutil.CollectAndCount(builderURLGauge))
}
