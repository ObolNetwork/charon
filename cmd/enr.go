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

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/p2p"
)

var enrCmd = &cobra.Command{
	Use:   "enr",
	Short: "Return this node's ENR",
	Long:  `Return information on this node's Ethereum Node Record (ENR)`,
	Args:  cobra.NoArgs,
	Run:   runENR,
}

func init() {
	rootCmd.AddCommand(enrCmd)
}

// Function for printing status of ENR for this instance
func runENR(_ *cobra.Command, _ []string) {
	p2pConfig := p2p.DefaultConfig()
	discoveryConfig := discovery.DefaultConfig()
	identityKey := identity.DefaultP2P().MustGet()
	localEnode, db, err := discovery.NewLocalEnode(discoveryConfig, p2pConfig, identityKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open peer DB")
	}
	defer db.Close()
	fmt.Println(localEnode.Node().String())
}
