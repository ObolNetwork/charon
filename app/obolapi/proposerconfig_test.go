// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net/http/httptest"
	"slices"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/testutil/obolapimock"
)

func TestProposerConfigAuthBlob(t *testing.T) {
	lockHash := make([]byte, 32)
	lockHash[0], lockHash[31] = 0xde, 0xad

	root, err := obolapi.ProposerConfigAuthBlob{LockHash: lockHash, ShareIndex: 3}.HashTreeRoot()
	require.NoError(t, err)

	// The SSZ root of a bytes32 and a uint64 is the sha256 of the lock hash and the little endian share index
	// padded to 32 bytes, as the Obol API computes it.
	var chunk [32]byte
	binary.LittleEndian.PutUint64(chunk[:], 3)

	require.Equal(t, sha256.Sum256(slices.Concat(lockHash, chunk[:])), root)

	// The vector of the Obol API spec.
	require.Equal(t, "a92ac9371a023ab9c9199a49689080310b63710e0324eb386b6c2e0956364e93", hex.EncodeToString(root[:]))
}

func TestProposerConfig(t *testing.T) {
	handler, addLockFiles := obolapimock.MockServer(false, nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	lock, keys, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(0)))

	cl, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	rev1 := signedProposerConfig(t, lock, keys, 1, 30_000_000)
	rev2 := signedProposerConfig(t, lock, keys, 2, 45_000_000)

	t.Run("lock not published", func(t *testing.T) {
		err := cl.PublishProposerConfig(t.Context(), rev1)
		require.ErrorIs(t, err, obolapi.ErrLockNotFound)
	})

	addLockFiles(lock)

	t.Run("nothing stored", func(t *testing.T) {
		_, err := cl.GetProposerConfig(t.Context(), lock.LockHash, 1, 0, keys[0])
		require.ErrorIs(t, err, obolapi.ErrProposerConfigNotFound)
	})

	require.NoError(t, cl.PublishProposerConfig(t.Context(), rev1))

	t.Run("same revision from another node", func(t *testing.T) {
		other := rev1
		other.Signatures = other.Signatures[1:]

		require.NoError(t, cl.PublishProposerConfig(t.Context(), other))
	})

	require.NoError(t, cl.PublishProposerConfig(t.Context(), rev2))

	t.Run("latest", func(t *testing.T) {
		got, err := cl.GetProposerConfig(t.Context(), lock.LockHash, 2, 0, keys[1])
		require.NoError(t, err)
		require.Equal(t, uint64(2), got.Revision)
		require.NoError(t, proposerconfig.Verify(got, lock))
	})

	t.Run("revision", func(t *testing.T) {
		got, err := cl.GetProposerConfig(t.Context(), lock.LockHash, 4, 1, keys[3])
		require.NoError(t, err)
		require.Equal(t, rev1.Config, got.Config)
		require.NoError(t, proposerconfig.Verify(got, lock))
	})

	t.Run("revision not stored", func(t *testing.T) {
		_, err := cl.GetProposerConfig(t.Context(), lock.LockHash, 1, 3, keys[0])
		require.ErrorIs(t, err, obolapi.ErrProposerConfigNotFound)
	})

	t.Run("another operator's key", func(t *testing.T) {
		_, err := cl.GetProposerConfig(t.Context(), lock.LockHash, 2, 0, keys[0])
		require.ErrorContains(t, err, "http GET failed")
		require.NotErrorIs(t, err, obolapi.ErrProposerConfigNotFound)
	})

	t.Run("lower revision than stored", func(t *testing.T) {
		stale := signedProposerConfig(t, lock, keys, 1, 60_000_000)

		err := cl.PublishProposerConfig(t.Context(), stale)
		require.ErrorIs(t, err, obolapi.ErrProposerConfigConflict)
	})

	t.Run("other document of a stored revision", func(t *testing.T) {
		other := signedProposerConfig(t, lock, keys, 2, 60_000_000)

		err := cl.PublishProposerConfig(t.Context(), other)
		require.ErrorIs(t, err, obolapi.ErrProposerConfigConflict)
	})
}

// signedProposerConfig returns the lock's proposer config revision with the gas limit, signed by all operators.
func signedProposerConfig(t *testing.T, lock cluster.Lock, keys []*k1.PrivateKey, revision, gasLimit uint64) proposerconfig.Document {
	t.Helper()

	fees := make([]string, len(lock.Validators))
	for i := range fees {
		fees[i] = "0x000000000000000000000000000000000000dead"
	}

	cfg, err := proposerconfig.NewConfig(lock, fees, gasLimit, nil)
	require.NoError(t, err)

	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: revision, Config: cfg}

	for i, key := range keys {
		sig, err := proposerconfig.Sign(doc, key)
		require.NoError(t, err)

		doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
	}

	require.NoError(t, proposerconfig.Verify(doc, lock))

	return doc
}
