package config

import (
	"github.com/spf13/pflag"
)

// P2P config keys.
const (
	KeyDiscV5  = "discv5"
	KeyP2P     = "p2p"
	KeyNodeDB  = "nodedb"
	KeyNetlist = "netlist"
)

// P2PFlags sets up Charon's p2p-related flags.
//
// Must only be called once in the program's lifetime.
func P2PFlags(flags *pflag.FlagSet) {
	flags.String(KeyDiscV5, ":30309", "Discovery (discv5) listen address")
	MustBindPFlag(KeyDiscV5, flags)

	flags.String(KeyP2P, ":13900", "P2P listen address")
	MustBindPFlag(KeyP2P, flags)

	flags.String(KeyNodeDB, "./data/nodedb", "Path to Node DB")
	MustBindPFlag(KeyNodeDB, flags)

	flags.String(KeyNetlist, "", "Network whitelist")
	MustBindPFlag(KeyNetlist, flags)
}
