// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

func newCreateEnrCmd(runFunc func(io.Writer, string) error) *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Create an Ethereum Node Record (ENR) private key to identify this charon client",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			return runFunc(cmd.OutOrStdout(), dataDir)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)

	return cmd
}

// runCreateEnrCmd stores a new charon-enr-private-key to disk and prints the ENR for the provided config.
// It returns an error if the key already exists.
func runCreateEnrCmd(w io.Writer, dataDir string) error {
	_, err := p2p.LoadPrivKey(dataDir)
	if err == nil {
		return errors.New("charon-enr-private-key already exists", z.Str("enr_path", p2p.KeyPath(dataDir)))
	}

	key, err := p2p.NewSavedPrivKey(dataDir)
	if err != nil {
		return err
	}

	r, err := enr.New(key)
	if err != nil {
		return err
	}

	keyPath := p2p.KeyPath(dataDir)

	_, _ = fmt.Fprintf(w, "Created ENR private key: %s\n", keyPath)
	_, _ = fmt.Fprintln(w, r.String())

	writeEnrWarning(w, keyPath)

	return nil
}

// writeEnrWarning writes backup key warning to the terminal.
func writeEnrWarning(w io.Writer, keyPath string) {
	var sb strings.Builder

	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** WARNING: Backup key **********************\n")
	_, _ = sb.WriteString(" PLEASE BACKUP YOUR KEY IMMEDIATELY! IF YOU LOSE YOUR KEY,\n")
	_, _ = sb.WriteString(" YOU WON'T BE ABLE TO PARTICIPATE IN RUNNING A CHARON CLUSTER.\n\n")
	_, _ = sb.WriteString(fmt.Sprintf(" YOU CAN FIND YOUR KEY IN %s\n", keyPath))
	_, _ = sb.WriteString("****************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}
