// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
)

func newVerifyLockCmd(runFunc func(io.Writer, string)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-lock <cluster-lock.json>",
		Short: "Verify cluster-lock.json file and exit",
		Long:  "Verify cluster-lock.json file and exit",
		Run: func(cmd *cobra.Command, args []string) { //nolint:revive // keep args variable name for clarity
			if len(args) != 1 {
				cmd.Printf("Usage: %s\n", cmd.UseLine())
			} else {
				runFunc(cmd.OutOrStdout(), args[0])
			}
		},
	}

	return cmd
}

func runVerifyLockCmd(out io.Writer, clusterLockFilePath string) {
	_, _ = fmt.Fprintf(out, "Reading cluster lock file: %s\n", clusterLockFilePath)

	verifyLock := func(lock cluster.Lock) error {
		_, _ = fmt.Fprintf(out, "Cluster lock version: %s\n", lock.Version)
		_, _ = fmt.Fprintf(out, "Expected cluster lock hash: %s\n", hex.EncodeToString(lock.LockHash))
		_, _ = fmt.Fprintf(out, "Expected cluster config hash: %s\n", hex.EncodeToString(lock.ConfigHash))
		_, _ = fmt.Fprintf(out, "Expected cluster definition hash: %s\n", hex.EncodeToString(lock.DefinitionHash))

		if err := lock.VerifyHashes(); err != nil {
			_, _ = fmt.Fprintf(out, "Cluster lock hash verification failed: %+v\n", err)
		} else {
			_, _ = fmt.Fprintf(out, "Cluster lock hash verification succeeded\n")
		}

		if err := lock.VerifySignatures(); err != nil {
			_, _ = fmt.Fprintf(out, "Cluster lock signature verification failed: %+v\n", err)
		} else {
			_, _ = fmt.Fprintf(out, "Cluster lock signature verification succeeded\n")
		}

		return nil
	}

	cluster, err := manifest.LoadCluster("", clusterLockFilePath, verifyLock)
	if err != nil {
		_, _ = fmt.Fprintf(out, "Failed to load cluster lock: %+v\n", err)
		return
	}

	hash := cluster.GetLatestMutationHash()
	_, _ = fmt.Fprintf(out, "Calculated cluster lock hash: %s\n", hex.EncodeToString(hash))
}
