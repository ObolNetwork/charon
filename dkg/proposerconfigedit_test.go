// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"
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

	// Node 0 writes the proposal file; half of the operators pass it, the others the equal change flags.
	proposal := writeTestProposal(t, clusterDir, 0, proposerconfig.Delta{GasLimit: 60_000_000})
	requireFilesUnchanged(t, clusterDir, before)

	var confs []dkg.ProposerConfigEditConfig

	for i := range n {
		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 60_000_000})
		if i >= n/2 {
			conf.Delta = proposerconfig.Delta{}
			conf.Proposal = &proposal
		}

		confs = append(confs, conf)
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

		archive, err := os.ReadFile(proposerconfig.ArchivePath(proposerconfig.FilePath(nodeDir(clusterDir, i)), 0))
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

		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: gasLimit}))
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

	clusterDir, lock, _ := setupEditCluster(t)
	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	// The absent operator misses the first edit, run by the threshold.
	var confs []dkg.ProposerConfigEditConfig

	for i := range n - 1 {
		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 60_000_000})
		conf.ParticipatingENRs = participatingENRs(lock, 0, 1, 2)
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

	absentFile, err := os.ReadFile(proposerconfig.FilePath(nodeDir(clusterDir, absent)))
	require.NoError(t, err)
	require.Equal(t, before[absent], absentFile)

	// The absent operator joins the next edit, adopting the signed revision 1 as its base. It passes a proposal
	// file for revision 2, ahead of its local revision 0.
	proposal := writeTestProposal(t, clusterDir, 0, proposerconfig.Delta{GasLimit: 80_000_000})
	require.Equal(t, uint64(2), proposal.Revision)

	confs = nil

	for i := range n {
		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 80_000_000})
		if i == absent {
			conf.Delta = proposerconfig.Delta{}
			conf.Proposal = &proposal
		}

		confs = append(confs, conf)
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
	archive, err := os.ReadFile(proposerconfig.ArchivePath(proposerconfig.FilePath(nodeDir(clusterDir, absent)), 0))
	require.NoError(t, err)
	require.Equal(t, before[absent], archive)
	require.NoFileExists(t, proposerconfig.ArchivePath(proposerconfig.FilePath(nodeDir(clusterDir, absent)), 1))
}

// TestEditProposalAhead verifies a proposal file ahead of the cluster fails when no operator holds a newer signed
// revision to adopt.
func TestEditProposalAhead(t *testing.T) {
	const (
		n     = editNodes
		ahead = 1
	)

	clusterDir, _, _ := setupEditCluster(t)
	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	proposal := writeTestProposal(t, clusterDir, ahead, proposerconfig.Delta{GasLimit: 60_000_000})
	proposal.Revision = 2

	// The other operators are stopped once the ahead one fails, instead of waiting for it until their timeout.
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{}, n)

	for i := range n {
		if i == ahead {
			continue
		}

		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 60_000_000})

		go func() {
			_, _ = dkg.RunProposerConfigEdit(ctx, conf)

			done <- struct{}{}
		}()
	}

	conf := editTestConfig(t, relayAddr, clusterDir, ahead, proposerconfig.Delta{})
	conf.Proposal = &proposal

	_, err := dkg.RunProposerConfigEdit(t.Context(), conf)

	cancel()

	for range n - 1 {
		<-done
	}

	require.ErrorContains(t, err, "no operator holds a newer signed revision")
	requireFilesUnchanged(t, clusterDir, before)
}

// TestEditExcludedOperator verifies an operator left out of the participating list cannot join the ceremony,
// which completes without it.
func TestEditExcludedOperator(t *testing.T) {
	const (
		n        = editNodes
		excluded = 3
	)

	clusterDir, lock, _ := setupEditCluster(t)
	relayAddr := relay.StartRelay(t.Context(), t)

	var confs []dkg.ProposerConfigEditConfig

	for i := range n {
		conf := editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 60_000_000})
		if i == excluded {
			conf.DKGConfig.Timeout = 15 * time.Second // Runs with the default of all operators, who do not expect it.
		} else {
			conf.ParticipatingENRs = participatingENRs(lock, 0, 1, 2)
		}

		confs = append(confs, conf)
	}

	results, errs := runEdits(confs)

	require.ErrorIs(t, errs[excluded], context.DeadlineExceeded)

	for i := range n - 1 {
		require.NoError(t, errs[i], "node %d", i)
		require.Equal(t, uint64(1), results[i].Revision)
		require.Equal(t, []int{0, 1, 2}, loadVerifiedDoc(t, clusterDir, i).SignerIndexes())
	}

	doc, err := proposerconfig.Load(proposerconfig.FilePath(nodeDir(clusterDir, excluded)), lock, cluster.NodeIdx{PeerIdx: excluded, ShareIdx: excluded + 1})
	require.NoError(t, err)
	require.Equal(t, uint64(0), doc.Revision)
}

func TestEditInvalidPeerCurrent(t *testing.T) {
	const (
		n       = editNodes
		hostile = 3
	)

	clusterDir, lock, cfg := setupEditCluster(t)
	relayAddr := relay.StartRelay(t.Context(), t)
	delta := proposerconfig.Delta{GasLimit: 60_000_000}

	// The hostile operator sends a higher revision with garbage signatures, then a valid round 2 message.
	forgedCfg, err := proposerconfig.Apply(lock, cfg, proposerconfig.Delta{GasLimit: 90_000_000})
	require.NoError(t, err)

	forged := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 5, Config: forgedCfg}
	for i := range n {
		forged.Signatures = append(forged.Signatures, proposerconfig.Signature{Operator: i, Signature: testutil.RandomBytes96()[:65]})
	}

	forgedJSON, err := proposerconfig.Marshal(forged)
	require.NoError(t, err)

	proposedCfg, err := proposerconfig.Apply(lock, cfg, delta)
	require.NoError(t, err)

	proposal := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 1, Config: proposedCfg}

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
		1: {Round: 1, CurrentRevision: forgedJSON, Participants: participants},
		2: {Round: 2, Proposal: proposalJSON, Signature: sig},
	}

	var confs []dkg.ProposerConfigEditConfig

	for i := range n {
		conf := editTestConfig(t, relayAddr, clusterDir, i, delta)
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

	clusterDir, lock, cfg := setupEditCluster(t)

	cfgA, err := proposerconfig.Apply(lock, cfg, proposerconfig.Delta{GasLimit: 60_000_000})
	require.NoError(t, err)

	cfgB, err := proposerconfig.Apply(lock, cfg, proposerconfig.Delta{GasLimit: 70_000_000})
	require.NoError(t, err)

	writeProposerConfigs(t, lock, clusterDir, []int{0, 1}, 1, cfgA)
	writeProposerConfigs(t, lock, clusterDir, []int{2, 3}, 1, cfgB)

	before := readProposerConfigFiles(t, clusterDir, n)
	relayAddr := relay.StartRelay(t.Context(), t)

	var confs []dkg.ProposerConfigEditConfig
	for i := range n {
		confs = append(confs, editTestConfig(t, relayAddr, clusterDir, i, proposerconfig.Delta{GasLimit: 80_000_000}))
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

	conf := editTestConfig(t, relayAddr, clusterDir, 0, proposerconfig.Delta{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err = dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorContains(t, err, "relay "+relayAddr+" already serves this node's charon run, pass different --p2p-relays (or CHARON_P2P_RELAYS)")
	require.False(t, networked.Load())
}

func TestEditWrongLock(t *testing.T) {
	clusterDir, _, _ := setupEditCluster(t)
	otherDir := createTestCluster(t, 4, 3, 2)

	other, err := os.ReadFile(proposerconfig.FilePath(nodeDir(otherDir, 0)))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(proposerconfig.FilePath(nodeDir(clusterDir, 0)), other, 0o644))

	conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err = dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorIs(t, err, proposerconfig.ErrLockHashMismatch)
	require.False(t, networked.Load())
}

func TestEditInvalidBase(t *testing.T) {
	clusterDir, lock, cfg := setupEditCluster(t)

	// Revision 1 without signatures.
	doc := proposerconfig.Document{Version: proposerconfig.Version, LockHash: lock.LockHash, Revision: 1, Config: cfg}
	require.NoError(t, proposerconfig.Write(proposerconfig.FilePath(nodeDir(clusterDir, 0)), doc, lock, cluster.NodeIdx{PeerIdx: 0, ShareIdx: 1}))

	conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{GasLimit: 60_000_000})
	networked := failOnNetworking(&conf)

	_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
	require.ErrorIs(t, err, proposerconfig.ErrInvalid)
	require.False(t, networked.Load())
}

func TestEditRejectedBeforeNetworking(t *testing.T) {
	clusterDir, lock, cfg := setupEditCluster(t)
	ndir := nodeDir(clusterDir, 0)

	gasLimit, err := cfg.GasLimit()
	require.NoError(t, err)

	tests := []struct {
		name          string
		delta         proposerconfig.Delta
		participating []string
		prepare       func(t *testing.T)
		errIs         error
		errContains   string
	}{
		{
			name:  "no change",
			delta: proposerconfig.Delta{GasLimit: gasLimit},
			errIs: proposerconfig.ErrNoChange,
		},
		{
			name:          "participating operators below threshold",
			delta:         proposerconfig.Delta{GasLimit: 60_000_000},
			participating: participatingENRs(lock, 0, 1),
			errContains:   "below the threshold",
		},
		{
			name:          "participating operators exclude this node",
			delta:         proposerconfig.Delta{GasLimit: 60_000_000},
			participating: participatingENRs(lock, 1, 2, 3),
			errContains:   "not among the participating operators",
		},
		{
			name:  "archive exists and differs",
			delta: proposerconfig.Delta{GasLimit: 60_000_000},
			prepare: func(t *testing.T) {
				t.Helper()
				require.NoError(t, os.WriteFile(proposerconfig.ArchivePath(proposerconfig.FilePath(ndir), 0), []byte("{}"), 0o644))
			},
			errContains: "archive exists and differs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.prepare != nil {
				test.prepare(t)
			}

			conf := editTestConfig(t, "", clusterDir, 0, test.delta)
			conf.ParticipatingENRs = test.participating
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

// TestEditProposalFile verifies the proposal file checks made before any networking.
func TestEditProposalFile(t *testing.T) {
	clusterDir, lock, cfg := setupEditCluster(t)

	gasLimit, err := cfg.GasLimit()
	require.NoError(t, err)

	proposal := writeTestProposal(t, clusterDir, 0, proposerconfig.Delta{GasLimit: 60_000_000})

	t.Run("existing file is not overwritten", func(t *testing.T) {
		conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{GasLimit: 70_000_000})
		conf.WriteProposalFile = path.Join(clusterDir, "proposal.json")
		require.NoError(t, os.WriteFile(conf.WriteProposalFile, []byte("{}"), 0o600))

		_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
		require.ErrorIs(t, err, os.ErrExist)
	})

	t.Run("unusable change is not written", func(t *testing.T) {
		conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{BuilderURLs: []string{"https://bücher.example"}})
		conf.WriteProposalFile = path.Join(t.TempDir(), "proposal.json")

		_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
		require.ErrorContains(t, err, "no ASCII hostname")
		require.NoFileExists(t, conf.WriteProposalFile)
	})

	t.Run("no change is not written", func(t *testing.T) {
		conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{GasLimit: gasLimit})
		conf.WriteProposalFile = path.Join(t.TempDir(), "proposal.json")

		_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
		require.ErrorIs(t, err, proposerconfig.ErrNoChange)
		require.NoFileExists(t, conf.WriteProposalFile)
	})

	tests := []struct {
		name        string
		mutate      func(*proposerconfig.Document)
		errIs       error
		errContains string
	}{
		{
			name:   "another cluster",
			mutate: func(d *proposerconfig.Document) { d.LockHash = []byte{1, 2, 3} },
			errIs:  proposerconfig.ErrLockHashMismatch,
		},
		{
			name:        "stale revision",
			mutate:      func(d *proposerconfig.Document) { d.Revision = 0 },
			errContains: "does not follow the cluster's proposer config revision",
		},
		{
			name:   "no change",
			mutate: func(d *proposerconfig.Document) { d.Config = cfg },
			errIs:  proposerconfig.ErrNoChange,
		},
		{
			name: "per validator gas limit",
			mutate: func(d *proposerconfig.Document) {
				d.Config.ProposerConfig = map[string]proposerconfig.Settings{fmt.Sprintf("%#x", lock.Validators[0].PubKey): {GasLimit: "1"}}
			},
			errContains: "sets more than fee_recipient",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := proposal
			test.mutate(&doc)

			conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{})
			conf.Proposal = &doc
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

	t.Run("not written from a proposal file", func(t *testing.T) {
		conf := editTestConfig(t, "", clusterDir, 0, proposerconfig.Delta{})
		conf.Proposal = &proposal
		conf.WriteProposalFile = path.Join(t.TempDir(), "proposal.json")

		_, err := dkg.RunProposerConfigEdit(t.Context(), conf)
		require.ErrorContains(t, err, "cannot be written from a proposal file")
	})
}

// writeTestProposal has node n write the proposal file of the delta, without a ceremony, and returns it parsed.
func writeTestProposal(t *testing.T, clusterDir string, n int, delta proposerconfig.Delta) proposerconfig.Document {
	t.Helper()

	conf := editTestConfig(t, "", clusterDir, n, delta)
	conf.WriteProposalFile = path.Join(t.TempDir(), "proposal.json")
	networked := failOnNetworking(&conf)

	res, err := dkg.RunProposerConfigEdit(t.Context(), conf)
	require.NoError(t, err)
	require.False(t, networked.Load())
	require.Equal(t, conf.WriteProposalFile, res.ProposalFile)
	require.Zero(t, res.Signers)

	b, err := os.ReadFile(conf.WriteProposalFile)
	require.NoError(t, err)

	doc, err := proposerconfig.ParseProposal(b)
	require.NoError(t, err)
	require.Equal(t, res.Revision, doc.Revision)

	return doc
}

// setupEditCluster returns a cluster whose nodes hold the same unsigned revision 0 proposer config, its lock and config.
func setupEditCluster(t *testing.T) (string, cluster.Lock, proposerconfig.Config) {
	t.Helper()

	clusterDir := createTestCluster(t, editNodes, 3, 2)
	lock := mustLoadLock(t, clusterDir)
	cfg := loadProposerConfig(t, nodeDir(clusterDir, 0))
	writeProposerConfigs(t, lock, clusterDir, getNodeIdxs(editNodes), 0, cfg)

	return clusterDir, lock, cfg
}

// editTestConfig returns node n's edit config with short sync windows.
func editTestConfig(t *testing.T, relayAddr, clusterDir string, n int, delta proposerconfig.Delta) dkg.ProposerConfigEditConfig {
	t.Helper()

	ndir := nodeDir(clusterDir, n)

	dkgConf := createDKGConfig(t, relayAddr)
	if relayAddr == "" {
		dkgConf.P2P.Relays = nil
	}

	dkgConf.ShutdownDelay = 0

	return dkg.ProposerConfigEditConfig{
		DKGConfig:          dkgConf,
		LockFilePath:       path.Join(ndir, clusterLockFile),
		PrivateKeyPath:     p2p.KeyPath(ndir),
		ProposerConfigFile: proposerconfig.FilePath(ndir),
		OverridesFile:      overridesPath(ndir),
		Delta:              delta,
	}
}

// participatingENRs returns the ENRs of the operators at the given lock indexes.
func participatingENRs(lock cluster.Lock, idxs ...int) []string {
	var resp []string
	for _, i := range idxs {
		resp = append(resp, lock.Operators[i].ENR)
	}

	return resp
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

	doc, err := proposerconfig.Load(proposerconfig.FilePath(nodeDir(clusterDir, n)), lock, nodeIdx)
	require.NoError(t, err)
	require.NoError(t, proposerconfig.Verify(doc, lock))

	return doc
}

func requireGasLimit(t *testing.T, doc proposerconfig.Document, want uint64) {
	t.Helper()

	got, err := doc.Config.GasLimit()
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func readProposerConfigFiles(t *testing.T, clusterDir string, n int) [][]byte {
	t.Helper()

	var files [][]byte

	for i := range n {
		b, err := os.ReadFile(proposerconfig.FilePath(nodeDir(clusterDir, i)))
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
		entries, err := os.ReadDir(path.Dir(proposerconfig.FilePath(nodeDir(clusterDir, i))))
		require.NoError(t, err)

		for _, e := range entries {
			require.NotContains(t, e.Name(), "revision", "node %d", i)
		}
	}
}
