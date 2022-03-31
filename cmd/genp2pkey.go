// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
)

func newGenP2PKeyCmd(runFunc func(io.Writer, p2p.Config, string) error) *cobra.Command {
	var (
		config  p2p.Config
		dataDir string
	)

	cmd := &cobra.Command{
		Use:   "gen-p2pkey",
		Short: "Generates a new p2p key",
		Long:  `Generates a new p2p authentication key (ecdsa-k1) and saves it to the data directory`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config, dataDir)
		},
	}

	bindDataDirFlag(cmd.Flags(), &dataDir)
	bindP2PFlags(cmd.Flags(), &config)

	return cmd
}

// runGenP2PKey stores a new p2pkey to disk and prints the ENR for the provided config.
func runGenP2PKey(w io.Writer, config p2p.Config, dataDir string) error {
	key, err := p2p.NewSavedPrivKey(dataDir)
	if err != nil {
		return err
	}

	localEnode, db, err := p2p.NewLocalEnode(config, key)
	if err != nil {
		return errors.Wrap(err, "failed to open peer DB")
	}
	defer db.Close()

	_, _ = fmt.Fprintf(w, "Created key: %s/p2pkey\n", dataDir)
	_, _ = fmt.Fprintln(w, localEnode.Node().String())

	return nil
}
