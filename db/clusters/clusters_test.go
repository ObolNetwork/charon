package clusters_test

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/obolnetwork/charon/db/clusters"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClusters(t *testing.T) {
	bdb, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	require.NoError(t, err)

	db := clusters.New(bdb)

	expect := clusters.Cluster{
		Hash: "1234",
	}

	id, err := db.Create(expect)
	require.NoError(t, err)

	actual, err := db.Get(id)
	require.NoError(t, err)
	require.Equal(t, expect, actual)

	actual, err = db.GetByHash(expect.Hash)
	require.NoError(t, err)
	require.Equal(t, expect, actual)
}
