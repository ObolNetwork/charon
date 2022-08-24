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
	"net"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func newCreateEnrCmd(runFunc func(io.Writer, p2p.Config, string) error) *cobra.Command {
	var (
		config  p2p.Config
		dataDir string
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Create an Ethereum Node Record (ENR) private key to identify this charon client",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config, dataDir)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)
	bindP2PFlags(cmd.Flags(), &config)

	return cmd
}

// runCreateEnrCmd stores a new charon-enr-private-key to disk and prints the ENR for the provided config.
// It returns an error if the key already exists.
func runCreateEnrCmd(w io.Writer, config p2p.Config, dataDir string) error {
	_, err := p2p.LoadPrivKey(dataDir)
	if err == nil {
		return errors.New("charon-enr-private-key already exists", z.Str("enr_path", p2p.KeyPath(dataDir)))
	}

	key, err := p2p.NewSavedPrivKey(dataDir)
	if err != nil {
		return err
	}

	keyPath := p2p.KeyPath(dataDir)

	enrStr, err := createENR(key, config)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Created ENR private key: %s\n", keyPath)
	_, _ = fmt.Fprintln(w, enrStr)

	writeEnrWarning(w, keyPath)

	return nil
}

func createENR(key *ecdsa.PrivateKey, config p2p.Config) (string, error) {
	tcpAddrs, err := config.ParseTCPAddrs()
	if err != nil {
		return "", err
	}

	var r enr.Record
	for _, addr := range tcpAddrs {
		r.Set(enr.IP(addr.IP))
		r.Set(enr.TCP(addr.Port))
	}

	udpAddr, err := net.ResolveUDPAddr("udp", config.UDPAddr)
	if err != nil {
		return "", errors.Wrap(err, "resolve udp address")
	}

	r.SetSeq(0)
	r.Set(enr.UDP(udpAddr.Port))
	if err = enode.SignV4(&r, key); err != nil {
		return "", errors.Wrap(err, "sign enr record")
	}

	return p2p.EncodeENR(r)
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
