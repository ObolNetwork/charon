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
	"crypto/elliptic"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newEnrCmd(runFunc func(io.Writer, p2p.Config, string) error) *cobra.Command {
	var (
		config  p2p.Config
		dataDir string
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Print this client's Ethereum Node Record",
		Long:  `Prints a newly generated Ethereum Node Record (ENR) from this node's charon-enr-private-key`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config, dataDir)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)
	bindP2PFlags(cmd.Flags(), &config)

	return cmd
}

// runNewENR loads the p2pkey from disk and prints the ENR for the provided config.
func runNewENR(w io.Writer, config p2p.Config, dataDir string) error {
	key, err := p2p.LoadPrivKey(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(dataDir))) //nolint:revive
	} else if err != nil {
		return err
	}

	localEnode, db, err := p2p.NewLocalEnode(config, key)
	if err != nil {
		return errors.Wrap(err, "failed to open peer DB")
	}
	defer db.Close()

	newEnr := localEnode.Node().String()

	r, err := p2p.DecodeENR(newEnr)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(w, newEnr)

	writeExpandedEnr(w, r.Signature(), r.Seq(), r.IdentityScheme(), pubkeyBytes(&key.PublicKey))

	return nil
}

// writeExpandedEnr writes the expanded form of ENR to the terminal.
func writeExpandedEnr(w io.Writer, sig []byte, seq uint64, id string, pubkey []byte) {
	var sb strings.Builder
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** Decoded ENR (see https://enr-viewer.com/ for additional fields) **********************\n")
	_, _ = sb.WriteString(fmt.Sprintf("signature: %#x\n", sig))
	_, _ = sb.WriteString(fmt.Sprintf("seq: %d\n", seq))
	_, _ = sb.WriteString(fmt.Sprintf("id: %s\n", id))
	_, _ = sb.WriteString(fmt.Sprintf("secp256k1 pubkey: %#x\n", pubkey))
	_, _ = sb.WriteString("********************************************************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}

// pubkeyBytes returns compressed public key bytes.
func pubkeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}

	return elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
}
