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
	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/p2p"
)

func newEnrCmd(runFunc func(io.Writer, p2p.Config, discovery.Config, string) error) *cobra.Command {
	var (
		p2pConfig       p2p.Config
		discoveryConfig discovery.Config
		dataDir         string
	)

	cmd := &cobra.Command{
		Use:   "enr",
		Short: "Return this node's ENR",
		Long:  `Return information on this node's Ethereum Node Record (ENR)`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), p2pConfig, discoveryConfig, dataDir)
		},
	}

	bindGeneralFlags(cmd.Flags(), &dataDir)
	bindP2PFlags(cmd.Flags(), &p2pConfig)
	bindDiscoveryFlags(cmd.Flags(), &discoveryConfig)

	return cmd
}

// Function for printing status of ENR for this instance.
func runNewENR(w io.Writer, p2pConfig p2p.Config, discoveryConfig discovery.Config, dataDir string) error {
	identityKey, err := identity.LoadOrCreatePrivKey(dataDir)
	if err != nil {
		return err
	}

	localEnode, db, err := discovery.NewLocalEnode(discoveryConfig, p2pConfig, identityKey)
	if err != nil {
		return errors.Wrap(err, "failed to open peer DB")
	}
	defer db.Close()

	_, _ = fmt.Fprintln(w, localEnode.Node().String())

	return nil
}
