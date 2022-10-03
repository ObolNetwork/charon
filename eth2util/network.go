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

package eth2util

import (
	"fmt"

	"github.com/obolnetwork/charon/app/errors"
)

// Network contains information about an Ethereum network.
type Network struct {
	// ChainID represents chainID of the network.
	ChainID int64
	// Name represents name of the network.
	Name string
	// ForkVersion represents fork version of the network in hex.
	ForkVersion string
}

var (
	Mainnet = Network{
		ChainID:     1,
		Name:        "mainnet",
		ForkVersion: "0x00000000",
	}
	Goerli = Network{
		ChainID:     5,
		Name:        "goerli",
		ForkVersion: "0x00001020",
	}
	Gnosis = Network{
		ChainID:     100,
		Name:        "gnosis",
		ForkVersion: "0x00000064",
	}
	Sepolia = Network{
		ChainID:     11155111,
		Name:        "sepolia",
		ForkVersion: "0x90000069",
	}
	Ropsten = Network{
		ChainID:     3,
		Name:        "ropsten",
		ForkVersion: "0x80000069",
	}
)

var supportedNetworks = map[Network]bool{
	Mainnet: true,
	Goerli:  true,
	Gnosis:  true,
	Sepolia: true,
	Ropsten: true,
}

// ForkVersionToChainID returns the chainID corresponding to the provided fork version.
func ForkVersionToChainID(forkVersion []byte) (int64, error) {
	for network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.ForkVersion {
			return network.ChainID, nil
		}
	}

	return -1, errors.New("invalid fork version")
}

// ForkVersionToNetwork returns the network name corresponding to the provided fork version.
func ForkVersionToNetwork(forkVersion []byte) (string, error) {
	for network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.ForkVersion {
			return network.Name, nil
		}
	}

	return "", errors.New("invalid fork version")
}
