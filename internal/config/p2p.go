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
