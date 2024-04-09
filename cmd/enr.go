// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"io"
	"io/fs"
	"strings"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

func newEnrCmd(runFunc func(io.Writer, string, bool) error) *cobra.Command {
	var (
		dataDir string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Print the ENR that identifies this client",
		Long:  `Prints an Ethereum Node Record (ENR) from this client's charon-enr-private-key. This serves as a public key that identifies this client to its peers.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), dataDir, verbose)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)
	bindEnrFlags(cmd.Flags(), &verbose)

	return cmd
}

// runNewENR loads the p2pkey from disk and prints the ENR for the provided config.
func runNewENR(w io.Writer, dataDir string, verbose bool) error {
	key, err := p2p.LoadPrivKey(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(dataDir))) //nolint:revive
	} else if err != nil {
		return err
	}

	r, err := enr.New(key)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(w, r.String())

	if !verbose {
		return nil
	}

	writeExpandedEnr(w, r, key)

	return nil
}

// writeExpandedEnr writes the expanded form of ENR to the terminal.
func writeExpandedEnr(w io.Writer, r enr.Record, privKey *k1.PrivateKey) {
	var sb strings.Builder
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** Decoded ENR (see https://enr-viewer.com/ for additional fields) **********************\n")
	_, _ = sb.WriteString(fmt.Sprintf("secp256k1 pubkey: %#x\n", privKey.PubKey().SerializeCompressed()))
	_, _ = sb.WriteString(fmt.Sprintf("signature: %#x\n", r.Signature))
	_, _ = sb.WriteString("********************************************************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}

func bindEnrFlags(flags *pflag.FlagSet, verbose *bool) {
	flags.BoolVar(verbose, "verbose", false, "Prints the expanded form of ENR.")
}
