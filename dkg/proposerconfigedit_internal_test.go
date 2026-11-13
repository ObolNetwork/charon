// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

func TestResolveEditBase(t *testing.T) {
	lock, keys := newEditTestLock(t)
	participants := []string{"a", "b", "c", "d"}

	rev0 := editTestDoc(t, lock, keys, 0, 36_000_000, nil)
	rev1 := editTestDoc(t, lock, keys, 1, 60_000_000, []int{0, 1, 2})
	rev1Other := editTestDoc(t, lock, keys, 1, 70_000_000, []int{0, 1, 2})
	rev2 := editTestDoc(t, lock, keys, 2, 80_000_000, []int{1, 2, 3})

	forged := rev2
	forged.Revision = 5
	forged.StoredHash = nil

	t.Run("adopts the highest valid revision", func(t *testing.T) {
		base, from, adopted, err := resolveEditBase(t.Context(), lock, 0, rev0, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
			1: rev1, 2: rev2, 3: rev2,
		}))
		require.NoError(t, err)
		require.True(t, adopted)
		require.Equal(t, 2, from)
		requireSameDoc(t, rev2, base)
	})

	t.Run("keeps own base when highest", func(t *testing.T) {
		base, _, adopted, err := resolveEditBase(t.Context(), lock, 0, rev1, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
			1: rev0, 2: rev1, 3: rev1,
		}))
		require.NoError(t, err)
		require.False(t, adopted)
		requireSameDoc(t, rev1, base)
	})

	t.Run("ignores invalid higher revision", func(t *testing.T) {
		base, _, adopted, err := resolveEditBase(t.Context(), lock, 0, rev1, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
			1: forged, 2: rev1, 3: rev1,
		}))
		require.NoError(t, err)
		require.False(t, adopted)
		requireSameDoc(t, rev1, base)
	})

	otherLock, otherKeys, _ := cluster.NewForT(t, 2, 3, 4, 1, rand.New(rand.NewSource(1)))

	for name, peerDoc := range map[string]proposerconfig.Document{
		"ignores unsigned higher revision":         editTestDoc(t, lock, keys, 2, 80_000_000, nil),
		"ignores under-signed higher revision":     editTestDoc(t, lock, keys, 2, 80_000_000, []int{0, 1}),
		"ignores higher revision for another lock": editTestDoc(t, otherLock, otherKeys, 3, 80_000_000, []int{0, 1, 2}),
	} {
		t.Run(name, func(t *testing.T) {
			base, _, adopted, err := resolveEditBase(t.Context(), lock, 0, rev1, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
				1: peerDoc, 2: rev1, 3: rev1,
			}))
			require.NoError(t, err)
			require.False(t, adopted)
			requireSameDoc(t, rev1, base)
		})
	}

	t.Run("same revision different hash", func(t *testing.T) {
		_, _, _, err := resolveEditBase(t.Context(), lock, 3, rev1Other, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
			0: rev1, 1: rev1, 2: rev1Other,
		}))
		require.ErrorContains(t, err, "operator 0 and operator 2 have a different signed revision 1")
		require.ErrorContains(t, err, "default.gas_limit: 60000000 -> 70000000")
	})

	t.Run("revision 0 differences are not inconsistent", func(t *testing.T) {
		other0 := editTestDoc(t, lock, keys, 0, 40_000_000, nil)

		base, _, adopted, err := resolveEditBase(t.Context(), lock, 0, rev0, participants, editTestMsgs(t, participants, map[int]proposerconfig.Document{
			1: other0, 2: rev0, 3: rev0,
		}))
		require.NoError(t, err)
		require.False(t, adopted)
		requireSameDoc(t, rev0, base)
	})

	t.Run("diverging participants", func(t *testing.T) {
		msgs := editTestMsgs(t, participants, map[int]proposerconfig.Document{1: rev0, 2: rev0, 3: rev0})
		msgs[2].Participants = []string{"a", "b", "c"}

		_, _, _, err := resolveEditBase(t.Context(), lock, 0, rev0, participants, msgs)
		require.ErrorContains(t, err, "operator 2 froze a different participant set")
	})
}

func TestCheckEditProposals(t *testing.T) {
	lock, keys := newEditTestLock(t)

	proposal := editTestDoc(t, lock, keys, 1, 60_000_000, nil)
	other := editTestDoc(t, lock, keys, 1, 70_000_000, nil)

	msgs := func(t *testing.T, docs map[int]proposerconfig.Document) map[int]*dkgpb.MsgProposerConfigEdit {
		t.Helper()

		resp := make(map[int]*dkgpb.MsgProposerConfigEdit)

		for operator, doc := range docs {
			b, err := proposerconfig.Marshal(doc)
			require.NoError(t, err)

			sig, err := proposerconfig.Sign(doc, keys[operator])
			require.NoError(t, err)

			resp[operator] = &dkgpb.MsgProposerConfigEdit{Round: 2, Proposal: b, Signature: sig}
		}

		return resp
	}

	t.Run("agree", func(t *testing.T) {
		sigs, err := checkEditProposals(lock, proposal, msgs(t, map[int]proposerconfig.Document{3: proposal, 1: proposal}))
		require.NoError(t, err)
		require.Len(t, sigs, 2)
		require.Equal(t, 1, sigs[0].Operator)
		require.Equal(t, 3, sigs[1].Operator)
	})

	t.Run("different proposal", func(t *testing.T) {
		_, err := checkEditProposals(lock, proposal, msgs(t, map[int]proposerconfig.Document{1: proposal, 2: other}))
		require.ErrorContains(t, err, "operator 2 proposed a different document:")
		require.ErrorContains(t, err, "default.gas_limit: 60000000 -> 70000000")
	})

	t.Run("signature of another operator", func(t *testing.T) {
		m := msgs(t, map[int]proposerconfig.Document{1: proposal, 2: proposal})
		m[2].Signature = m[1].GetSignature()

		_, err := checkEditProposals(lock, proposal, m)
		require.ErrorIs(t, err, proposerconfig.ErrInvalid)
		require.ErrorContains(t, err, "operator signature")
	})
}

// newEditTestLock returns a 3 of 4 lock with two validators and the operator keys.
func newEditTestLock(t *testing.T) (cluster.Lock, []*k1.PrivateKey) {
	t.Helper()

	lock, keys, _ := cluster.NewForT(t, 2, 3, 4, 0, rand.New(rand.NewSource(0)))

	return lock, keys
}

// editTestDoc returns a document with the gas limit at revision, signed by the given operators.
func editTestDoc(t *testing.T, lock cluster.Lock, keys []*k1.PrivateKey, revision, gasLimit uint64, signers []int) proposerconfig.Document {
	t.Helper()

	fees := slices.Repeat([]string{testFeeAddr}, len(lock.Validators))

	cfg, err := proposerconfig.NewConfig(lock, fees, gasLimit, nil)
	require.NoError(t, err)

	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: revision, Config: cfg}

	for _, operator := range signers {
		sig, err := proposerconfig.Sign(doc, keys[operator])
		require.NoError(t, err)

		doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: operator, Signature: sig})
	}

	return doc
}

// editTestMsgs returns round 1 messages carrying the documents as current.
func editTestMsgs(t *testing.T, participants []string, docs map[int]proposerconfig.Document) map[int]*dkgpb.MsgProposerConfigEdit {
	t.Helper()

	resp := make(map[int]*dkgpb.MsgProposerConfigEdit)

	for operator, doc := range docs {
		b, err := proposerconfig.Marshal(doc)
		require.NoError(t, err)

		resp[operator] = &dkgpb.MsgProposerConfigEdit{Round: 1, CurrentRevision: b, Participants: participants}
	}

	return resp
}

// requireSameDoc checks the documents have the same revision hash and signers.
func requireSameDoc(t *testing.T, want, got proposerconfig.Document) {
	t.Helper()

	wantHash, err := want.Hash()
	require.NoError(t, err)

	gotHash, err := got.Hash()
	require.NoError(t, err)

	require.Equal(t, wantHash, gotHash)
	require.Equal(t, want.SignerIndexes(), got.SignerIndexes())
}

func TestRelayOnlyConfig(t *testing.T) {
	conf := Config{
		Timeout: time.Hour,
		P2P: p2p.Config{
			Relays:       []string{"https://relay.example.com"},
			TCPAddrs:     []string{"0.0.0.0:3610"},
			UDPAddrs:     []string{"0.0.0.0:3630"},
			ExternalIP:   "203.0.113.1",
			ExternalHost: "node.example.com",
		},
	}

	got := relayOnlyConfig(conf)
	require.Equal(t, p2p.Config{Relays: []string{"https://relay.example.com"}}, got.P2P)
	require.Equal(t, time.Hour, got.Timeout)
	require.Equal(t, []string{"0.0.0.0:3610"}, conf.P2P.TCPAddrs, "input unchanged")
}

func TestWriteEditResultRechecksFile(t *testing.T) {
	lock, keys := newEditTestLock(t)
	nodeIdx := cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}

	rev1 := editTestDoc(t, lock, keys, 1, 60_000_000, []int{0, 1, 2})
	rev1Other := editTestDoc(t, lock, keys, 1, 70_000_000, []int{0, 1, 2})
	proposal := editTestDoc(t, lock, keys, 2, 80_000_000, nil)

	var sigs []proposerconfig.Signature

	for _, operator := range []int{0, 1, 2} {
		sig, err := proposerconfig.Sign(proposal, keys[operator])
		require.NoError(t, err)

		sigs = append(sigs, proposerconfig.Signature{Operator: operator, Signature: sig})
	}

	write := func(t *testing.T, path string, doc proposerconfig.Document) []byte {
		t.Helper()

		require.NoError(t, proposerconfig.Write(path, doc, lock, nodeIdx))

		b, err := os.ReadFile(path)
		require.NoError(t, err)

		return b
	}

	t.Run("unchanged file is archived and replaced", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proposer-config.json")
		before := write(t, path, rev1)

		doc, err := writeEditResult(lock, nodeIdx, path, proposal, sigs, &rev1)
		require.NoError(t, err)
		require.EqualValues(t, 2, doc.Revision)

		archived, err := os.ReadFile(proposerconfig.ArchivePath(path, 1))
		require.NoError(t, err)
		require.Equal(t, before, archived)
	})

	t.Run("file replaced during the ceremony", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proposer-config.json")
		write(t, path, rev1)
		replaced := write(t, path, rev1Other)

		_, err := writeEditResult(lock, nodeIdx, path, proposal, sigs, &rev1)
		require.ErrorContains(t, err, "proposer config file changed during the ceremony")

		b, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, replaced, b)
		require.NoFileExists(t, proposerconfig.ArchivePath(path, 1))
	})

	t.Run("file created during the ceremony", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proposer-config.json")
		created := write(t, path, rev1)

		_, err := writeEditResult(lock, nodeIdx, path, proposal, sigs, nil)
		require.ErrorContains(t, err, "proposer config file changed during the ceremony")

		b, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, created, b)
		require.NoFileExists(t, proposerconfig.ArchivePath(path, 0))
	})
}

func TestWarnFeeRecipientDriftOnce(t *testing.T) {
	lock, keys := newEditTestLock(t)

	var logs zaptest.Buffer

	log.InitLogfmtForT(t, &logs)

	// Both validators' fee recipients differ from the lock, and the gas limit from the initial config.
	doc := editTestDoc(t, lock, keys, 0, 60_000_000, nil)
	warnFeeRecipientDrift(t.Context(), lock, doc, filepath.Join(t.TempDir(), "absent.json"))

	require.Equal(t, 1, strings.Count(logs.String(), "level=warn"), logs.String())
	require.Contains(t, logs.String(), "differences=2")
	require.NotContains(t, logs.String(), "gas_limit")
}
