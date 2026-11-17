// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

// proposerAPITest is a 4 node cluster at revision 1 and an Obol API mock, which holds its lock if published.
type proposerAPITest struct {
	dir  string
	lock cluster.Lock
	api  string
}

func newProposerAPITest(t *testing.T, lockPublished bool) proposerAPITest {
	t.Helper()

	dir := newProposerTestCluster(t)

	lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(dir, 0), clusterLockFile), "", true)
	require.NoError(t, err)

	handler, addLockFiles := obolapimock.MockServer(false, nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	if lockPublished {
		addLockFiles(*lock)
	}

	return proposerAPITest{dir: dir, lock: *lock, api: srv.URL}
}

func (b proposerAPITest) publishConfig(node int) proposerPublishConfig {
	return proposerPublishConfig{
		LockFile:           path.Join(nodeDir(b.dir, node), clusterLockFile),
		ProposerConfigFile: proposerconfig.FilePath(nodeDir(b.dir, node)),
		PublishAddress:     b.api,
		PublishTimeout:     defaultPublishTimeout,
		NoVerify:           true,
	}
}

func (b proposerAPITest) fetchConfig(node int) proposerFetchConfig {
	return proposerFetchConfig{
		LockFile:           path.Join(nodeDir(b.dir, node), clusterLockFile),
		PrivateKeyFile:     path.Join(nodeDir(b.dir, node), enrPrivateKeyFile),
		ProposerConfigFile: proposerconfig.FilePath(nodeDir(b.dir, node)),
		PublishAddress:     b.api,
		PublishTimeout:     defaultPublishTimeout,
		NoVerify:           true,
	}
}

func (b proposerAPITest) nodeIdx(node int) cluster.NodeIdx {
	return cluster.NodeIdx{PeerIdx: node, ShareIdx: node + 1}
}

// load returns the node's proposer config file.
func (b proposerAPITest) load(t *testing.T, node int) proposerconfig.Document {
	t.Helper()

	doc, err := proposerconfig.Load(proposerconfig.FilePath(nodeDir(b.dir, node)), b.lock, b.nodeIdx(node))
	require.NoError(t, err)

	return doc
}

// signedRevision returns the node's revision with the gas limit changed, as the next revision signed by all operators.
func (b proposerAPITest) signedRevision(t *testing.T, node int, gasLimit string) proposerconfig.Document {
	t.Helper()

	doc := b.load(t, node)
	doc.Revision++
	doc.Config.DefaultConfig.GasLimit = gasLimit
	doc.Signatures, doc.StoredHash = nil, nil

	for i := range b.lock.Operators {
		key, err := k1util.Load(path.Join(nodeDir(b.dir, i), enrPrivateKeyFile))
		require.NoError(t, err)

		sig, err := proposerconfig.Sign(doc, key)
		require.NoError(t, err)

		doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
	}

	require.NoError(t, proposerconfig.Verify(doc, b.lock))

	return doc
}

func TestProposerPublish(t *testing.T) {
	t.Run("lock not published", func(t *testing.T) {
		b := newProposerAPITest(t, false)

		err := runProposerPublish(t.Context(), new(bytes.Buffer), b.publishConfig(0))
		require.ErrorIs(t, err, obolapi.ErrLockNotFound)
	})

	t.Run("published", func(t *testing.T) {
		b := newProposerAPITest(t, true)

		var out bytes.Buffer
		require.NoError(t, runProposerPublish(t.Context(), &out, b.publishConfig(2)))
		require.Equal(t, "Proposer config revision 1 published to "+b.api+": charon alpha proposer fetch fetches it.\n", out.String())

		// Every node may publish the same revision.
		require.NoError(t, runProposerPublish(t.Context(), new(bytes.Buffer), b.publishConfig(0)))
	})

	t.Run("revision 0", func(t *testing.T) {
		b := newProposerAPITest(t, true)

		doc := b.load(t, 1)
		doc.Revision, doc.Signatures, doc.StoredHash = 0, nil, nil
		require.NoError(t, proposerconfig.Write(proposerconfig.FilePath(nodeDir(b.dir, 1)), doc, b.lock, b.nodeIdx(1)))

		err := runProposerPublish(t.Context(), new(bytes.Buffer), b.publishConfig(1))
		require.ErrorContains(t, err, "unsigned revision 0, which is not published")
	})
}

func TestProposerFetch(t *testing.T) {
	b := newProposerAPITest(t, true)

	// Revisions 1 and 2 are published, every node file holds revision 1.
	require.NoError(t, runProposerPublish(t.Context(), new(bytes.Buffer), b.publishConfig(0)))

	cl, err := obolapi.New(b.api)
	require.NoError(t, err)

	rev2 := b.signedRevision(t, 0, "45000000")
	require.NoError(t, cl.PublishProposerConfig(t.Context(), rev2))

	t.Run("lost file", func(t *testing.T) {
		require.NoError(t, os.Remove(proposerconfig.FilePath(nodeDir(b.dir, 1))))

		var out bytes.Buffer
		require.NoError(t, runProposerFetch(t.Context(), &out, b.fetchConfig(1)))
		require.Contains(t, out.String(), "Proposer config revision 2, signed by 4 of 4 operators (0, 1, 2, 3), written to ")
		require.Contains(t, out.String(), "Restart your validator client")

		doc := b.load(t, 1)
		require.Equal(t, uint64(2), doc.Revision)
		require.Equal(t, "45000000", doc.Config.DefaultConfig.GasLimit)
	})

	t.Run("earlier revision archived", func(t *testing.T) {
		require.NoError(t, runProposerFetch(t.Context(), new(bytes.Buffer), b.fetchConfig(2)))
		require.Equal(t, uint64(2), b.load(t, 2).Revision)
		require.FileExists(t, proposerconfig.ArchivePath(proposerconfig.FilePath(nodeDir(b.dir, 2)), 1))
	})

	t.Run("already holds it", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, runProposerFetch(t.Context(), &out, b.fetchConfig(1)))
		require.Equal(t, "The proposer config file already holds revision 2, nothing written.\n", out.String())
	})

	t.Run("earlier revision refused", func(t *testing.T) {
		conf := b.fetchConfig(1)
		conf.Revision = 1

		err := runProposerFetch(t.Context(), new(bytes.Buffer), conf)
		require.ErrorContains(t, err, "holds a later revision than the fetched one")
		require.Equal(t, uint64(2), b.load(t, 1).Revision)
	})

	t.Run("revision not published", func(t *testing.T) {
		conf := b.fetchConfig(3)
		conf.Revision = 3

		err := runProposerFetch(t.Context(), new(bytes.Buffer), conf)
		require.ErrorIs(t, err, obolapi.ErrProposerConfigNotFound)
		require.Equal(t, uint64(1), b.load(t, 3).Revision)
	})
}

func TestProposerFetchUntrusted(t *testing.T) {
	b := newProposerAPITest(t, true)

	// The API returns revision 2 with its gas limit changed after signing.
	tampered := b.signedRevision(t, 0, "45000000")
	tampered.Config.DefaultConfig.GasLimit = "1"

	body, err := proposerconfig.Marshal(tampered)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	conf := b.fetchConfig(1)
	conf.PublishAddress = srv.URL

	err = runProposerFetch(t.Context(), new(bytes.Buffer), conf)
	require.ErrorContains(t, err, "verify fetched proposer config")
	require.Equal(t, uint64(1), b.load(t, 1).Revision)
}
