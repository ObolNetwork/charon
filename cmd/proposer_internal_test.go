// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/eth2util"
)

const proposerTestFeeRecipient = "0x000000000000000000000000000000000000dEaD"

// newProposerTestCluster creates a 4 node cluster with 2 validators, its proposer config signed at revision 1.
func newProposerTestCluster(t *testing.T) string {
	t.Helper()

	return newProposerTestClusterWith(t, proposerTestFeeRecipient, proposerTestFeeRecipient)
}

// newProposerTestClusterWith is newProposerTestCluster with the fee recipient of each of the 2 validators.
func newProposerTestClusterWith(t *testing.T, feeRecipients ...string) string {
	t.Helper()

	dir := t.TempDir()
	conf := clusterConfig{
		ClusterDir:        dir,
		Name:              t.Name(),
		NumNodes:          4,
		Threshold:         3,
		NumDVs:            2,
		Network:           eth2util.Hoodi.Name,
		TargetGasLimit:    36000000,
		FeeRecipientAddrs: feeRecipients,
		WithdrawalAddrs:   []string{proposerTestFeeRecipient, proposerTestFeeRecipient},
		InsecureKeys:      true,
	}
	require.NoError(t, createClusterT(t.Context(), io.Discard, conf))

	return dir
}

// runProposerCmd runs charon alpha proposer with the args and returns its output.
func runProposerCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()

	root := newRootCmd(newAlphaCmd(newProposerCmd(runProposerStatus,
		newProposerListCmd(runProposerList),
		newProposerCreateCmd(runProposerCreate),
	)))

	var out bytes.Buffer

	root.SetArgs(append([]string{"alpha", "proposer"}, args...))
	root.SetOut(&out)
	root.SetErr(io.Discard)

	err := root.Execute()

	return out.String(), err
}

func TestProposerCreate(t *testing.T) {
	dir := newProposerTestCluster(t)
	output := path.Join(t.TempDir(), "proposal.json")

	// Node 0's lock with node 2's proposer config file, and no node key.
	out, err := runProposerCmd(t, "create",
		"--lock-file="+path.Join(nodeDir(dir, 0), clusterLockFile),
		"--proposer-config-file="+proposerconfig.FilePath(nodeDir(dir, 2)),
		"--output-file="+output,
		"--gas-limit=60000000",
	)
	require.NoError(t, err)
	require.Contains(t, out, "Proposer config revision 2 (hash 0x")
	require.Contains(t, out, "changes from revision 1:")
	require.Contains(t, out, "60000000")
	require.Contains(t, out, "then all run charon alpha proposer edit "+output)

	b, err := os.ReadFile(output)
	require.NoError(t, err)

	doc, err := proposerconfig.ParseProposal(b)
	require.NoError(t, err)
	require.Equal(t, uint64(2), doc.Revision)
	require.Equal(t, "60000000", doc.Config.DefaultConfig.GasLimit)

	_, err = runProposerCmd(t, "create", "--lock-file="+path.Join(nodeDir(dir, 0), clusterLockFile),
		"--proposer-config-file="+proposerconfig.FilePath(nodeDir(dir, 0)), "--output-file="+output, "--gas-limit=70000000")
	require.ErrorIs(t, err, os.ErrExist)
}

func TestProposerStatus(t *testing.T) {
	dir := newProposerTestCluster(t)
	lockFile := "--lock-file=" + path.Join(nodeDir(dir, 0), clusterLockFile)

	t.Run("signed", func(t *testing.T) {
		out, err := runProposerCmd(t, lockFile, "--proposer-config-file="+proposerconfig.FilePath(nodeDir(dir, 1)))
		require.NoError(t, err)
		require.Contains(t, out, `Cluster "TestProposerStatus", lock 0x`)
		require.Contains(t, out, "4 operators, threshold 3")
		require.Contains(t, out, "Proposer config revision 1, signed by 4 of 4 operators: 0, 1, 2, 3\n")
		require.Contains(t, out, strings.ToLower(proposerTestFeeRecipient)+" (default), 0 validator(s) with their own")
		require.Contains(t, out, "builders       none")
		require.Contains(t, out, "Change it: charon alpha proposer create")
	})

	t.Run("no file", func(t *testing.T) {
		missing := path.Join(t.TempDir(), "proposer-config.json")

		out, err := runProposerCmd(t, lockFile, "--proposer-config-file="+missing)
		require.NoError(t, err)
		require.Contains(t, out, "No proposer config file at "+missing)
	})

	loadDoc := func(t *testing.T, node int) (cluster.Lock, proposerconfig.Document) {
		t.Helper()

		lock, err := dkg.LoadAndVerifyClusterLock(t.Context(), path.Join(nodeDir(dir, 0), clusterLockFile), "", true)
		require.NoError(t, err)

		doc, err := proposerconfig.Load(proposerconfig.FilePath(nodeDir(dir, node)), *lock, cluster.NodeIdx{PeerIdx: node, ShareIdx: node + 1})
		require.NoError(t, err)

		return *lock, doc
	}

	t.Run("unsigned revision 0", func(t *testing.T) {
		lock, doc := loadDoc(t, 1)
		doc.Revision, doc.Signatures, doc.StoredHash = 0, nil, nil

		file := path.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, proposerconfig.Write(file, doc, lock, cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}))

		out, err := runProposerCmd(t, lockFile, "--proposer-config-file="+file)
		require.NoError(t, err)
		require.Contains(t, out, "Proposer config revision 0, unsigned")
		require.Contains(t, out, "gas limit")
	})

	t.Run("unverified file is not shown", func(t *testing.T) {
		lock, doc := loadDoc(t, 1)
		doc.Signatures = doc.Signatures[:1]

		file := path.Join(t.TempDir(), "proposer-config.json")
		require.NoError(t, proposerconfig.Write(file, doc, lock, cluster.NodeIdx{PeerIdx: 1, ShareIdx: 2}))

		out, err := runProposerCmd(t, lockFile, "--proposer-config-file="+file)
		require.NoError(t, err)
		require.Contains(t, out, "Proposer config revision 1 does not verify against the cluster lock: not enough signatures")
		require.NotContains(t, out, "gas limit")
	})

	// Malformed locks, loaded unverified, are reported instead of panicking.
	for name, mutate := range map[string]func(map[string]any){
		"short lock hash": func(lock map[string]any) { lock["lock_hash"] = "0x12" },
		"missing pubshare": func(lock map[string]any) {
			val, ok := lock["distributed_validators"].([]any)[0].(map[string]any)
			require.True(t, ok)

			val["public_shares"] = val["public_shares"].([]any)[:2]
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path.Join(nodeDir(dir, 0), clusterLockFile))
			require.NoError(t, err)

			var lock map[string]any
			require.NoError(t, json.Unmarshal(b, &lock))
			mutate(lock)

			b, err = json.Marshal(lock)
			require.NoError(t, err)

			file := path.Join(t.TempDir(), clusterLockFile)
			require.NoError(t, os.WriteFile(file, b, 0o600))

			out, err := runProposerCmd(t, "--lock-file="+file, "--no-verify", "--proposer-config-file="+proposerconfig.FilePath(nodeDir(dir, 1)))
			require.NoError(t, err)
			require.Contains(t, out, `Cluster "TestProposerStatus", lock 0x`)
		})
	}

	t.Run("no lock", func(t *testing.T) {
		out, err := runProposerCmd(t, "--lock-file="+path.Join(t.TempDir(), "missing.json"))
		require.NoError(t, err)
		require.Contains(t, out, "Cannot show the proposer config: load cluster lock")
	})
}

func TestProposerList(t *testing.T) {
	def := strings.ToLower(proposerTestFeeRecipient)

	run := func(t *testing.T, dir string, extra ...string) string {
		t.Helper()

		args := []string{
			"list",
			"--lock-file=" + path.Join(nodeDir(dir, 0), clusterLockFile),
			"--proposer-config-file=" + proposerconfig.FilePath(nodeDir(dir, 3)),
		}

		out, err := runProposerCmd(t, append(args, extra...)...)
		require.NoError(t, err)

		return out
	}

	t.Run("all on the default", func(t *testing.T) {
		dir := newProposerTestCluster(t)

		out := run(t, dir)
		require.Equal(t, "Proposer config revision 1, 2 validators\n"+
			"Default: fee recipient "+def+", gas limit 200000000\n"+
			"All validators use the default fee recipient.\n"+
			"Builders: none\n", out)

		var list proposerListJSON
		require.NoError(t, json.Unmarshal([]byte(run(t, dir, "--json")), &list))
		require.Equal(t, proposerListJSON{
			Revision:   1,
			Validators: 2,
			Default:    proposerDefaultJSON{FeeRecipient: def, GasLimit: "200000000"},
			Own:        []proposerOwnJSON{},
		}, list)
	})

	t.Run("own fee recipient", func(t *testing.T) {
		const own = "0x000000000000000000000000000000000000bEEF"

		dir := newProposerTestClusterWith(t, proposerTestFeeRecipient, own)

		out := run(t, dir)
		require.Contains(t, out, "Default: fee recipient "+def+", gas limit")
		require.Contains(t, out, "1 validator(s) with their own fee recipient:\n  PUBKEY")
		require.Equal(t, 1, strings.Count(out, strings.ToLower(own)))
		require.Equal(t, 1, strings.Count(out, def))

		var list proposerListJSON
		require.NoError(t, json.Unmarshal([]byte(run(t, dir, "--json")), &list))
		require.Equal(t, 2, list.Validators)
		require.Len(t, list.Own, 1)
		require.Equal(t, strings.ToLower(own), list.Own[0].FeeRecipient)
		require.Len(t, list.Own[0].Pubkey, 98)
	})
}

func TestBuilderSummary(t *testing.T) {
	builder := &proposerconfig.Builder{
		MinBid:              "1",
		BuilderBoostFactor:  "90",
		MaxExecutionPayment: "2",
		Builders:            []proposerconfig.BuilderEntry{{URL: "https://user:secret@builder.example/key?token=0x1234#frag"}, {URL: "https://b.example"}},
	}

	require.Equal(t, "none", builderSummary(nil))
	require.Equal(t, "https://builder.example/xxxxx, https://b.example · min bid 1 gwei · boost factor 90% · max execution payment 2 gwei",
		builderSummary(builder))

	// The JSON list hides the credentials too, and leaves the config's builder as is.
	require.Nil(t, redactedBuilder(nil))

	b, err := json.Marshal(redactedBuilder(builder))
	require.NoError(t, err)
	require.Contains(t, string(b), `"url":"https://builder.example/xxxxx"`)

	for _, secret := range []string{"user", "secret", "key", "token", "0x1234", "frag"} {
		require.NotContains(t, string(b), secret)
	}

	require.Equal(t, "https://user:secret@builder.example/key?token=0x1234#frag", builder.Builders[0].URL)
}
