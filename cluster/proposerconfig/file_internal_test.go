// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

func testDoc(t *testing.T, lock cluster.Lock) Document {
	t.Helper()

	builder := &Builder{
		MinBid:              "0",
		BuilderBoostFactor:  "100",
		MaxExecutionPayment: "0",
		Builders:            []BuilderEntry{{URL: "https://b1.example"}},
	}

	cfg, err := NewConfig(lock, []string{addrA, addrB}, DefaultGasLimit, builder)
	require.NoError(t, err)

	doc := Document{
		Version:  Version,
		LockHash: lock.LockHash,
		Revision: 2,
		Config:   cfg,
		Signatures: []Signature{
			{Operator: 2, Signature: []byte{0xbb, 0xbb}},
			{Operator: 0, Signature: []byte{0xaa}},
		},
	}

	hash, err := doc.Hash()
	require.NoError(t, err)

	doc.StoredHash = hash[:]

	return doc
}

func TestWriteLoadRoundTrip(t *testing.T) {
	lock := testLock(t, 2)
	nodeIdx := cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}
	doc := testDoc(t, lock)
	path := filepath.Join(t.TempDir(), "vc-config", "proposer-config.json")

	require.NoError(t, Write(path, doc, lock, nodeIdx))

	loaded, err := Load(path, lock, nodeIdx)
	require.NoError(t, err)

	// Signatures are written sorted by operator.
	doc.Signatures = []Signature{doc.Signatures[1], doc.Signatures[0]}
	require.Equal(t, doc, loaded)

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	testutil.RequireGoldenBytes(t, b)

	var raw struct {
		RevisionHash string `json:"revision_hash"`
	}
	require.NoError(t, json.Unmarshal(b, &raw))

	hash, err := doc.Hash()
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%#x", hash), raw.RevisionHash)

	// Field order.
	s := string(b)
	last := -1

	for _, k := range []string{"version", "lock_hash", "revision", "revision_hash", "proposer_config", "default_config", "signatures"} {
		idx := strings.Index(s, `"`+k+`"`)
		require.Greater(t, idx, last, k)

		last = idx
	}

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, 0o644, info.Mode().Perm())
}

func TestMarshalRoundTrip(t *testing.T) {
	lock := testLock(t, 2)
	doc := testDoc(t, lock)

	b, err := Marshal(doc)
	require.NoError(t, err)
	testutil.RequireGoldenBytes(t, b)

	got, err := Unmarshal(b)
	require.NoError(t, err)

	doc.Signatures = []Signature{doc.Signatures[1], doc.Signatures[0]}
	require.Equal(t, doc, got)

	// Nil and empty builders marshal identically.
	doc.Config.DefaultConfig.Builder.Builders = nil
	b2, err := Marshal(doc)
	require.NoError(t, err)

	doc.Config.DefaultConfig.Builder.Builders = []BuilderEntry{}
	b3, err := Marshal(doc)
	require.NoError(t, err)
	require.Equal(t, b2, b3)
}

func TestLoadIntegerVersion(t *testing.T) {
	lock := testLock(t, 1)
	path := filepath.Join(t.TempDir(), "proposer-config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"proposer_config":{},"default_config":{"gas_limit":"30000000"}}`), 0o644))

	// A pre-release file with an integer version does not decode.
	_, err := Load(path, lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1})
	require.ErrorContains(t, err, "load proposer config")
	require.NotErrorIs(t, err, ErrNotFound)
}

func TestLoadMissingLockHash(t *testing.T) {
	lock := testLock(t, 1)
	path := filepath.Join(t.TempDir(), "proposer-config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":"v1.0.0","proposer_config":{},"default_config":{"gas_limit":"30000000"}}`), 0o644))

	// A hand-written file without a lock hash is invalid, not another cluster's.
	_, err := Load(path, lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1})
	require.ErrorIs(t, err, ErrInvalid)
	require.NotErrorIs(t, err, ErrLockHashMismatch)
}

func TestLoadForeignPubshares(t *testing.T) {
	lock := testLock(t, 2)
	path := filepath.Join(t.TempDir(), "proposer-config.json")

	require.NoError(t, Write(path, testDoc(t, lock), lock, cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}))

	_, err := Load(path, lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1})
	require.ErrorContains(t, err, "unknown pubshare")
}

func TestLoadLockHashMismatch(t *testing.T) {
	lock := testLock(t, 2)
	other, _, _ := cluster.NewForT(t, 2, 3, 4, 8, rand.New(rand.NewSource(8)))
	path := filepath.Join(t.TempDir(), "proposer-config.json")
	nodeIdx := cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}

	// The other cluster's file has entries keyed by pubshares unknown to this lock.
	doc := testDoc(t, other)
	require.NotEmpty(t, doc.Config.ProposerConfig)
	require.NoError(t, Write(path, doc, other, nodeIdx))

	_, err := Load(path, lock, nodeIdx)
	require.ErrorIs(t, err, ErrLockHashMismatch)
}

func TestLoadMissing(t *testing.T) {
	lock := testLock(t, 1)

	_, err := Load(filepath.Join(t.TempDir(), "nope.json"), lock, cluster.NodeIdx{})
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestWriteAtomic(t *testing.T) {
	lock := testLock(t, 2)
	dir := filepath.Join(t.TempDir(), "a", "b")

	require.NoError(t, Write(filepath.Join(dir, "p.json"), testDoc(t, lock), lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "p.json", entries[0].Name())
}

func TestArchiveIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proposer-config.json")
	archive := filepath.Join(dir, "proposer-config-revision-0.json")

	require.Equal(t, archive, ArchivePath(path, 0))
	require.NoError(t, os.WriteFile(path, []byte("current"), 0o644))

	require.NoError(t, CheckArchive(path, 0))
	require.NoError(t, Archive(path, 0))

	b, err := os.ReadFile(archive)
	require.NoError(t, err)
	require.Equal(t, "current", string(b))

	require.NoError(t, CheckArchive(path, 0))
	require.NoError(t, Archive(path, 0))

	require.NoError(t, os.WriteFile(path, []byte("changed"), 0o644))
	require.ErrorContains(t, CheckArchive(path, 0), "move it away first")
	require.ErrorContains(t, Archive(path, 0), "move it away first")
}
