package cmd

import (
	"fmt"

	"github.com/obolnetwork/charon/discovery"
	"github.com/obolnetwork/charon/identity"
	"github.com/obolnetwork/charon/internal/config"
	"github.com/obolnetwork/charon/p2p"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	nodeDBPath := viper.GetString(config.KeyNodeDB)
	p2pConfig := p2p.DefaultConfig()
	identityKey := identity.DefaultP2P().MustGet()
	db, err := discovery.NewPeerDB(nodeDBPath, p2pConfig, identityKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open peer DB")
	}
	defer db.Close()
	fmt.Println(db.Local.Node().String())
}
