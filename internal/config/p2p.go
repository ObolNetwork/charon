package config

import (
	"github.com/spf13/pflag"
)

// P2P config keys.
const (
	KeyP2P    = "p2p"
	KeyNodeDB = "nodedb"
)

// P2PFlags sets up Charon's p2p-related flags.
//
// Must only be called once in the program's lifetime.
func P2PFlags(flags *pflag.FlagSet) {
	flags.String(KeyP2P, ":13900", "P2P listen address")
	MustBindPFlag(KeyP2P, flags)

	flags.String(KeyNodeDB, "./data/nodedb", "Path to Node DB")
	MustBindPFlag(KeyNodeDB, flags)
}
