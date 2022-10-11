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
	"net"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newEnrCmd(runFunc func(io.Writer, p2p.Config, string, bool) error) *cobra.Command {
	var (
		config  p2p.Config
		dataDir string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Prints a new ENR for this node",
		Long:  `Prints a newly generated Ethereum Node Record (ENR) from this node's charon-enr-private-key`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config, dataDir, verbose)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)
	bindP2PFlags(cmd, &config)
	bindEnrFlags(cmd.Flags(), &verbose)

	return cmd
}

// runNewENR loads the p2pkey from disk and prints the ENR for the provided config.
func runNewENR(w io.Writer, config p2p.Config, dataDir string, verbose bool) error {
	key, err := p2p.LoadPrivKey(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(dataDir))) //nolint:revive
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

	writeExpandedEnr(w, r, key)

	return nil
}

// writeExpandedEnr writes the expanded form of ENR to the terminal.
func writeExpandedEnr(w io.Writer, r enr.Record, privKey *ecdsa.PrivateKey) {
	var sb strings.Builder
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** Decoded ENR (see https://enr-viewer.com/ for additional fields) **********************\n")
	_, _ = sb.WriteString(fmt.Sprintf("secp256k1 pubkey: %#x\n", pubkeyHex(privKey.PublicKey)))
	_, _ = sb.WriteString(fmt.Sprintf("signature: %#x\n", r.Signature()))
	_, _ = sb.WriteString(fmt.Sprintf("seq: %d\n", r.Seq()))
	_, _ = sb.WriteString(fmt.Sprintf("id: %s\n", r.IdentityScheme()))
	_, _ = sb.WriteString(enrNetworkingKeys(r))
	_, _ = sb.WriteString("********************************************************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}

// pubkeyHex compresses the provided public key and returns the 0x hex encoded string.
func pubkeyHex(pubkey ecdsa.PublicKey) string {
	b := crypto.CompressPubkey(&pubkey)

	return fmt.Sprintf("%#x", b)
}

func bindEnrFlags(flags *pflag.FlagSet, verbose *bool) {
	flags.BoolVar(verbose, "verbose", false, "Prints the expanded form of ENR.")
}

// enrNetworkingKeys returns a string containing the non-empty networking keys (ips and ports) present in the ENR record.
func enrNetworkingKeys(r enr.Record) string {
	var (
		sb   strings.Builder
		ip   enr.IPv4
		ip6  enr.IPv6
		tcp  enr.TCP
		tcp6 enr.TCP6
		udp  enr.UDP
		udp6 enr.UDP6
	)

	if err := r.Load(&ip); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %s\n", ip.ENRKey(), net.IP(ip).String()))
	}

	if err := r.Load(&ip6); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %s\n", ip6.ENRKey(), net.IP(ip6).String()))
	}

	if err := r.Load(&tcp); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %d\n", tcp.ENRKey(), tcp))
	}

	if err := r.Load(&tcp6); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %d\n", tcp6.ENRKey(), tcp6))
	}

	if err := r.Load(&udp); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %d\n", udp.ENRKey(), udp))
	}

	if err := r.Load(&udp6); err == nil {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %d\n", udp6.ENRKey(), udp6))
	}

	return sb.String()
}
