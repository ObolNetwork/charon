// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/relay"
)

const (
	editProtocolID protocol.ID = "/charon/proposerconfig/1.0.0"
	// editNodes is the number of operators of the edit test clusters, with threshold 3.
	editNodes = 4
)

func TestEditAllAgree(t *testing.T) {
	const n = editNodes

	clusterDir, _, _ := setupEditCluster(t)
	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	var confs []dkg.ProposerConfigEditConfig
	for i := range n {
		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: 60_000_000}))
	}

	results, errs := runEdits(confs)

	for i := range n {
		require.NoError(t, errs[i], "node %d", i)

		doc := loadVerifiedDoc(t, clusterDir, i)
		require.Equal(t, uint64(1), doc.Revision)
		require.Equal(t, getNodeIdxs(n), doc.SignerIndexes())
		requireGasLimit(t, doc, 60_000_000)

		hash, err := doc.Hash()
		require.NoError(t, err)
		require.Equal(t, dkg.ProposerConfigEditResult{Revision: 1, Hash: hash, Signers: n, Operators: n}, results[i])

		archive, err := os.ReadFile(proposerconfig.ArchivePath(proposerConfigPath(nodeDir(clusterDir, i)), 0))
		require.NoError(t, err)
		require.Equal(t, before[i], archive)
	}
}

func TestEditProposalMismatch(t *testing.T) {
	const (
		n       = editNodes
		deviant = 2
	)

	clusterDir, _, _ := setupEditCluster(t)
	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	var confs []dkg.ProposerConfigEditConfig

	for i := range n {
		gasLimit := uint64(60_000_000)
		if i == deviant {
			gasLimit = 70_000_000
		}

		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: gasLimit}))
	}

	_, errs := runEdits(confs)

	for i := range n {
		// Diffs read from this node's proposal to the peer's.
		if i == deviant {
			require.ErrorContains(t, errs[i], "proposed a different document", "node %d", i)
			require.ErrorContains(t, errs[i], "default.gas_limit: 70000000 -> 60000000", "node %d", i)
		} else {
			require.ErrorContains(t, errs[i], "operator 2 proposed a different document", "node %d", i)
			require.ErrorContains(t, errs[i], "default.gas_limit: 60000000 -> 70000000", "node %d", i)
		}
	}

	requireFilesUnchanged(t, clusterDir, before)
}

func TestEditThreshold(t *testing.T) {
	const (
		n      = editNodes
		absent = 3
	)

	clusterDir, _, _ := setupEditCluster(t)
	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	// The absent operator misses the first edit, run by the threshold.
	var confs []dkg.ProposerConfigEditConfig

	for i := range n - 1 {
		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: 60_000_000})
		conf.MinOperators = 3
		confs = append(confs, conf)
	}

	results, errs := runEdits(confs)

	for i := range n - 1 {
		require.NoError(t, errs[i], "node %d", i)
		require.Equal(t, uint64(1), results[i].Revision)
		require.Equal(t, 3, results[i].Signers)

		doc := loadVerifiedDoc(t, clusterDir, i)
		require.Equal(t, []int{0, 1, 2}, doc.SignerIndexes())
	}

	absentFile, err := os.ReadFile(proposerConfigPath(nodeDir(clusterDir, absent)))
	require.NoError(t, err)
	require.Equal(t, before[absent], absentFile)

	// The absent operator joins the next edit, adopting the signed revision 1 as its base.
	confs = nil
	for i := range n {
		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: 80_000_000}))
	}

	results, errs = runEdits(confs)

	for i := range n {
		require.NoError(t, errs[i], "node %d", i)
		require.Equal(t, uint64(2), results[i].Revision)
		require.Equal(t, i == absent, results[i].Adopted, "node %d", i)

		doc := loadVerifiedDoc(t, clusterDir, i)
		require.Equal(t, uint64(2), doc.Revision)
		require.Equal(t, getNodeIdxs(n), doc.SignerIndexes())
		requireGasLimit(t, doc, 80_000_000)
	}

	// The absent operator archives the revision 0 file it had on disk.
	archive, err := os.ReadFile(proposerconfig.ArchivePath(proposerConfigPath(nodeDir(clusterDir, absent)), 0))
	require.NoError(t, err)
	require.Equal(t, before[absent], archive)
	require.NoFileExists(t, proposerconfig.ArchivePath(proposerConfigPath(nodeDir(clusterDir, absent)), 1))
}

func TestEditLateJoiner(t *testing.T) {
	const n = editNodes

	clusterDir, lock, _ := setupEditCluster(t)
	relayAddr := relay.StartRelay(t.Context(), t)

	// Only the peer with the smaller ID dials over the relay, so a late joiner with the highest ID is only
	// reached by the frozen nodes' clients to absent peers.
	peers, err := lock.Peers()
	require.NoError(t, err)

	late := slices.MaxFunc(peers, func(a, b p2p.Peer) int { return strings.Compare(string(a.ID), string(b.ID)) }).Index

	// The others linger after the ceremony so the late joiner reaches their frozen sync servers.
	var (
		confs  []dkg.ProposerConfigEditConfig
		others []int
	)

	for i := range n {
		if i == late {
			continue
		}

		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: 60_000_000})
		conf.MinOperators = 3
		conf.DKGConfig.ShutdownDelay = 15 * time.Second
		confs = append(confs, conf)
		others = append(others, i)
	}

	done := make(chan []error, 1)

	go func() {
		_, errs := runEdits(confs)
		done <- errs
	}()

	require.Eventually(t, func() bool {
		for _, i := range others {
			doc, err := proposerconfig.Load(proposerConfigPath(nodeDir(clusterDir, i)), lock, cluster.NodeIdx{PeerIdx: i, ShareIdx: i + 1})
			if err != nil || doc.Revision != 1 {
				return false
			}
		}

		return true
	}, 30*time.Second, 50*time.Millisecond)

	conf := editTestConfig(t, relayAddr, clusterDir, late, proposerconfig.Patch{GasLimit: 60_000_000})
	conf.MinOperators = 3
	conf.DKGConfig.Timeout = 10 * time.Second

	_, err = dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorContains(t, err, "ceremony already in progress")

	for i, err := range <-done {
		require.NoError(t, err, "node %d", others[i])
	}
}

func TestEditInvalidPeerCurrent(t *testing.T) {
	const (
		n       = editNodes
		hostile = 3
	)

	clusterDir, lock, content := setupEditCluster(t)
	relayAddr := relay.StartRelay(t.Context(), t)
	patch := proposerconfig.Patch{GasLimit: 60_000_000}

	// The hostile operator sends a higher revision with garbage signatures, then a valid round 2 message.
	forgedContent, err := proposerconfig.Apply(lock, content, proposerconfig.Patch{GasLimit: 90_000_000})
	require.NoError(t, err)

	forged := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 5, Content: forgedContent}
	for i := range n {
		forged.Signatures = append(forged.Signatures, proposerconfig.Signature{Operator: i, Signature: testutil.RandomBytes96()[:65]})
	}

	forgedJSON, err := proposerconfig.Marshal(forged)
	require.NoError(t, err)

	proposedContent, err := proposerconfig.Apply(lock, content, patch)
	require.NoError(t, err)

	proposal := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 1, Content: proposedContent}

	proposalJSON, err := proposerconfig.Marshal(proposal)
	require.NoError(t, err)

	key, err := k1util.Load(p2p.KeyPath(nodeDir(clusterDir, hostile)))
	require.NoError(t, err)

	sig, err := proposerconfig.Sign(proposal, key)
	require.NoError(t, err)

	peers, err := lock.Peers()
	require.NoError(t, err)

	var participants []string
	for _, p := range peers {
		participants = append(participants, p.ID.String())
	}

	slices.Sort(participants)

	hostileMsgs := map[uint32]*dkgpb.MsgProposerConfigEdit{
		1: {Round: 1, Current: forgedJSON, Participants: participants},
		2: {Round: 2, Proposal: proposalJSON, Signature: sig},
	}

	var confs []dkg.ProposerConfigEditConfig

	for i := range n {
		conf := editTestConfig(t, relayAddr, clusterDir, i, patch)
		if i == hostile {
			conf.DKGConfig.TestConfig.P2PNodeCallback = hijackEditHandler(t, hostileMsgs)
		}

		confs = append(confs, conf)
	}

	results, errs := runEdits(confs)

	for i := range n {
		require.NoError(t, errs[i], "node %d", i)
		require.False(t, results[i].Adopted, "node %d", i)
		require.Equal(t, uint64(1), results[i].Revision)

		doc := loadVerifiedDoc(t, clusterDir, i)
		requireGasLimit(t, doc, 60_000_000)
	}
}

func TestEditSameRevisionDifferentHash(t *testing.T) {
	const n = editNodes

	clusterDir, lock, content := setupEditCluster(t)

	contentA, err := proposerconfig.Apply(lock, content, proposerconfig.Patch{GasLimit: 60_000_000})
	require.NoError(t, err)

	contentB, err := proposerconfig.Apply(lock, content, proposerconfig.Patch{GasLimit: 70_000_000})
	require.NoError(t, err)

	writeProposerConfigs(t, lock, clusterDir, []int{0, 1}, 1, contentA)
	writeProposerConfigs(t, lock, clusterDir, []int{2, 3}, 1, contentB)

	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	var confs []dkg.ProposerConfigEditConfig
	for i := range n {
		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Patch{GasLimit: 80_000_000}))
	}

	_, errs := runEdits(confs)

	for i := range n {
		require.ErrorContains(t, errs[i], "different signed revision 1", "node %d", i)
		require.ErrorContains(t, errs[i], "default.gas_limit: 60000000 -> 70000000", "node %d", i)
	}

	requireFilesUnchanged(t, clusterDir, before)
}

func TestEditRelayOccupied(t *testing.T) {
	clusterDir, _, _ := setupEditCluster(t)
	relayAddr := relay.StartRelay(t.Context(), t)

	// A host with node 0's key, standing in for its running charon run, holds a reservation on the relay.
	key, err := k1util.Load(p2p.KeyPath(nodeDir(clusterDir, 0)))
	require.NoError(t, err)

	h := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), key)
	defer h.Close()

	relays, err := p2p.NewRelays(t.Context(), []string{relayAddr}, "lockhash", "uuid")
	require.NoError(t, err)

	relayPeer, ok := relays[0].Peer()
	require.True(t, ok)

	require.NoError(t, h.Connect(t.Context(), relayPeer.AddrInfo()))

	_, err = client.Reserve(t.Context(), h, relayPeer.AddrInfo())
	require.NoError(t, err)

	conf := editTestConfig(t, relayAddr, clusterDir, 0, proposerconfig.Patch{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err = dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorContains(t, err, "relay "+relayAddr+" already serves this node's charon run, pass different --p2p-relays (or CHARON_P2P_RELAYS)")
	require.False(t, networked.Load())
}

func TestEditWrongLock(t *testing.T) {
	clusterDir, _, _ := setupEditCluster(t)
	otherDir := createTestCluster(t, 4, 3, 2)

	other, err := os.ReadFile(proposerConfigPath(nodeDir(otherDir, 0)))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(proposerConfigPath(nodeDir(clusterDir, 0)), other, 0o644))

	conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Patch{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err = dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorIs(t, err, proposerconfig.ErrLockHashMismatch)
	require.False(t, networked.Load())
}

func TestEditInvalidBase(t *testing.T) {
	clusterDir, lock, content := setupEditCluster(t)

	// Revision 1 without signatures.
	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 1, Content: content}
	require.NoError(t, proposerconfig.Write(proposerConfigPath(nodeDir(clusterDir, 0)), doc, lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}))

	conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Patch{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorIs(t, err, proposerconfig.ErrInvalid)
	require.False(t, networked.Load())
}

func TestEditRejectedBeforeNetworking(t *testing.T) {
	clusterDir, _, content := setupEditCluster(t)
	ndir := nodeDir(clusterDir, 0)

	gasLimit, err := content.GasLimit()
	require.NoError(t, err)

	tests := []struct {
		name         string
		patch        proposerconfig.Patch
		minOperators int
		prepare      func(t *testing.T)
		errIs        error
		errContains  string
	}{
		{
			name:  "no change",
			patch: proposerconfig.Patch{GasLimit: gasLimit},
			errIs: proposerconfig.ErrNoChange,
		},
		{
			name:         "min operators below threshold",
			patch:        proposerconfig.Patch{GasLimit: 60_000_000},
			minOperators: 2,
			errContains:  "min operators",
		},
		{
			name:         "min operators above operator count",
			patch:        proposerconfig.Patch{GasLimit: 60_000_000},
			minOperators: 5,
			errContains:  "min operators",
		},
		{
			name:  "archive exists and differs",
			patch: proposerconfig.Patch{GasLimit: 60_000_000},
			prepare: func(t *testing.T) {
				t.Helper()
				require.NoError(t, os.WriteFile(proposerconfig.ArchivePath(proposerConfigPath(ndir), 0), []byte("{}"), 0o644))
			},
			errContains: "archive exists and differs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.prepare != nil {
				test.prepare(t)
			}

			conf := editTestConfig(t, "", clusterDir, 0, test.patch)
			conf.MinOperators = test.minOperators
			networked := failOnNetworking(&conf)

			_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
			if test.errIs != nil {
				require.ErrorIs(t, err, test.errIs)
			} else {
				require.ErrorContains(t, err, test.errContains)
			}

			require.False(t, networked.Load())
		})
	}
}

// setupEditCluster returns a cluster whose nodes hold the same unsigned revision 0 proposer config, its lock and content.
func setupEditCluster(t *testing.T) (string, cluster.Lock, proposerconfig.Content) {
	t.Helper()

	clusterDir := createTestCluster(t, editNodes, 3, 2)
	lock := mustLoadLock(t, clusterDir)
	content := loadProposerConfigContent(t, nodeDir(clusterDir, 0))
	writeProposerConfigs(t, lock, clusterDir, getNodeIdxs(editNodes), 0, content)

	return clusterDir, lock, content
}

// editTestConfig returns node n's edit config with short sync windows.
func editTestConfig(t *testing.T, relayAddr, clusterDir string, n int, patch proposerconfig.Patch) dkg.ProposerConfigEditConfig {
	t.Helper()

	ndir := nodeDir(clusterDir, n)

	dkgConf := createDKGConfig(t, relayAddr)
	if relayAddr == "" {
		dkgConf.P2P.Relays = nil
	}

	dkgConf.ShutdownDelay = 0
	dkgConf.TestConfig.StragglerWait = 500 * time.Millisecond
	dkgConf.TestConfig.PostFreezeTimeout = 10 * time.Second

	return dkg.ProposerConfigEditConfig{
		DKGConfig:          dkgConf,
		LockFilePath:       path.Join(ndir, clusterLockFile),
		PrivateKeyPath:     p2p.KeyPath(ndir),
		ProposerConfigFile: proposerConfigPath(ndir),
		OverridesFile:      overridesPath(ndir),
		Patch:              patch,
	}
}

// runEdits runs the edits concurrently and returns their results and errors in order.
func runEdits(confs []dkg.ProposerConfigEditConfig) ([]dkg.ProposerConfigEditResult, []error) {
	results := make([]dkg.ProposerConfigEditResult, len(confs))
	errs := make([]error, len(confs))
	done := make(chan struct{}, len(confs))

	for i, conf := range confs {
		go func() {
			results[i], errs[i] = dkg.RunProposerConfigEdit(context.Background(), conf)

			done <- struct{}{}
		}()
	}

	for range confs {
		<-done
	}

	return results, errs
}

// failOnNetworking returns a flag set if the edit creates its p2p host.
func failOnNetworking(conf *dkg.ProposerConfigEditConfig) *atomic.Bool {
	var networked atomic.Bool

	conf.DKGConfig.TestConfig.P2PNodeCallback = func(host.Host) { networked.Store(true) }

	return &networked
}

// hijackEditHandler returns a p2p node callback replacing the node's edit handler with one answering msgs.
func hijackEditHandler(t *testing.T, msgs map[uint32]*dkgpb.MsgProposerConfigEdit) func(host.Host) {
	t.Helper()

	return func(h host.Host) {
		go func() {
			// Wait for the ceremony's handler, then replace it.
			for !slices.Contains(h.Mux().Protocols(), editProtocolID) {
				time.Sleep(time.Millisecond)
			}

			p2p.RegisterHandler("hostile", h, editProtocolID,
				func() proto.Message { return new(dkgpb.MsgProposerConfigEdit) },
				func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
					return msgs[req.(*dkgpb.MsgProposerConfigEdit).GetRound()], true, nil
				})
		}()
	}
}

func mustLoadLock(t *testing.T, clusterDir string) cluster.Lock {
	t.Helper()

	lock, _ := loadLockAndNodeIdx(t, nodeDir(clusterDir, 0))

	return lock
}

// loadVerifiedDoc returns node n's proposer config document after verifying it.
func loadVerifiedDoc(t *testing.T, clusterDir string, n int) proposerconfig.Document {
	t.Helper()

	lock, nodeIdx := loadLockAndNodeIdx(t, nodeDir(clusterDir, n))

	doc, err := proposerconfig.Load(proposerConfigPath(nodeDir(clusterDir, n)), lock, nodeIdx)
	require.NoError(t, err)
	require.NoError(t, proposerconfig.Verify(doc, lock))

	return doc
}

func requireGasLimit(t *testing.T, doc proposerconfig.Document, want uint64) {
	t.Helper()

	got, err := doc.Content.GasLimit()
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func readProposerConfigFiles(t *testing.T, clusterDir string, n int) [][]byte {
	t.Helper()

	var files [][]byte

	for i := range n {
		b, err := os.ReadFile(proposerConfigPath(nodeDir(clusterDir, i)))
		require.NoError(t, err)

		files = append(files, b)
	}

	return files
}

// requireFilesUnchanged checks the proposer config files equal before and no archive was written.
func requireFilesUnchanged(t *testing.T, clusterDir string, before [][]byte) {
	t.Helper()

	after := readProposerConfigFiles(t, clusterDir, len(before))
	require.Equal(t, before, after)

	for i := range before {
		entries, err := os.ReadDir(path.Dir(proposerConfigPath(nodeDir(clusterDir, i))))
		require.NoError(t, err)

		for _, e := range entries {
			require.NotContains(t, e.Name(), "revision", "node %d", i)
		}
	}
}
