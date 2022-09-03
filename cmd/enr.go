// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newEnrCmd(runFunc func(io.Writer, p2p.Config, string, bool) error) *cobra.Command {
	var (
		config      p2p.Config
		dataDir     string
		privKeyFile string
		verbose     bool
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Prints a new ENR for this node",
		Long:  `Prints a newly generated Ethereum Node Record (ENR) from this node's charon-enr-private-key`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config, privKeyFile, verbose)
		},
	}

	bindDataDirFlag(cmd, &dataDir)
	bindPrivKeyFileFlag(cmd.Flags(), &privKeyFile)
	bindP2PFlags(cmd.Flags(), &config)
	bindEnrFlags(cmd.Flags(), &verbose)

	return cmd
}

// runNewENR loads the p2pkey from disk and prints the ENR for the provided config.
func runNewENR(w io.Writer, config p2p.Config, privKeyFile string, verbose bool) error {
	key, err := p2p.LoadPrivKey(privKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", privKeyFile)) //nolint:revive
	} else if err != nil {
		return err
	}

	r, err := createENR(key, config)
	if err != nil {
		return err
	}

	enrStr, err := p2p.EncodeENR(r)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(w, enrStr)

	if !verbose {
		return nil
	}

	writeExpandedEnr(w, r.Signature(), r.Seq(), pubkeyHex(key.PublicKey))

	return nil
}

// writeExpandedEnr writes the expanded form of ENR to the terminal.
func writeExpandedEnr(w io.Writer, sig []byte, seq uint64, pubkey string) {
	var sb strings.Builder
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** Decoded ENR (see https://enr-viewer.com/ for additional fields) **********************\n")
	_, _ = sb.WriteString(fmt.Sprintf("secp256k1 pubkey: %#x\n", pubkey))
	_, _ = sb.WriteString(fmt.Sprintf("signature: %#x\n", sig))
	_, _ = sb.WriteString(fmt.Sprintf("seq: %d\n", seq))
	_, _ = sb.WriteString("********************************************************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}

// pubkeyHex returns compressed public key bytes.
func pubkeyHex(pubkey ecdsa.PublicKey) string {
	b := crypto.CompressPubkey(&pubkey)

	return fmt.Sprintf("%#x", b)
}

func bindEnrFlags(flags *pflag.FlagSet, verbose *bool) {
	flags.BoolVar(verbose, "verbose", false, "Prints the expanded form of ENR.")
}

func bindPrivKeyFileFlag(flags *pflag.FlagSet, privKeyFile *string) {
	flags.StringVar(privKeyFile, "private-key", ".charon/charon-enr-private-key", "The path where your enr private key will be saved.")
}
