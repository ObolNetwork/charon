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

	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/eth2util"
)

const proposerTestFeeRecipient = "0x000000000000000000000000000000000000dEaD"

// newProposerTestCluster creates a 4 node cluster with 2 validators, its proposer config signed at revision 1.
func newProposerTestCluster(t *testing.T) string {
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
		FeeRecipientAddrs: []string{proposerTestFeeRecipient, proposerTestFeeRecipient},
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
		require.Contains(t, out, "Proposer config revision 1, signed by 4/4 operators")
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

	t.Run("no lock", func(t *testing.T) {
		out, err := runProposerCmd(t, "--lock-file="+path.Join(t.TempDir(), "missing.json"))
		require.NoError(t, err)
		require.Contains(t, out, "Cannot show the proposer config: load cluster lock")
	})
}

func TestProposerList(t *testing.T) {
	dir := newProposerTestCluster(t)
	args := []string{
		"list",
		"--lock-file=" + path.Join(nodeDir(dir, 0), clusterLockFile),
		"--proposer-config-file=" + proposerconfig.FilePath(nodeDir(dir, 3)),
	}

	out, err := runProposerCmd(t, args...)
	require.NoError(t, err)
	require.Contains(t, out, "Proposer config revision 1\n")
	require.Contains(t, out, "INDEX  PUBKEY")
	require.Equal(t, 2, strings.Count(out, strings.ToLower(proposerTestFeeRecipient)+"  default"))
	require.Contains(t, out, "Builders of all validators: none")

	out, err = runProposerCmd(t, append(args, "--json")...)
	require.NoError(t, err)

	var list proposerListJSON
	require.NoError(t, json.Unmarshal([]byte(out), &list))
	require.Equal(t, uint64(1), list.Revision)
	require.Len(t, list.Validators, 2)
	require.Nil(t, list.Builder)

	for _, v := range list.Validators {
		require.Equal(t, strings.ToLower(proposerTestFeeRecipient), v.FeeRecipient)
		require.False(t, v.OwnFeeRecipient)
		require.NotEmpty(t, v.GasLimit)
	}
}

func TestBuilderSummary(t *testing.T) {
	require.Equal(t, "none", builderSummary(nil))
	require.Equal(t, "https://user:xxxxx@builder.example/xxxxx, https://b.example · min bid 1 gwei · boost factor 90% · max execution payment 2 gwei",
		builderSummary(&proposerconfig.Builder{
			MinBid:              "1",
			BuilderBoostFactor:  "90",
			MaxExecutionPayment: "2",
			Builders:            []proposerconfig.BuilderEntry{{URL: "https://user:secret@builder.example/key"}, {URL: "https://b.example"}},
		}))
}
