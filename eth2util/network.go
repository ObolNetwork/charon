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
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
)

const Prater = "prater"

// Network contains information about an Ethereum network.
type Network struct {
	// ChainID represents chainID of the network.
	ChainID int64
	// Name represents name of the network.
	Name string
	// ForkVersionHex represents fork version of the network in hex.
	ForkVersionHex string
}

var (
	Mainnet = Network{
		ChainID:        1,
		Name:           "mainnet",
		ForkVersionHex: "0x00000000",
	}
	Goerli = Network{
		ChainID:        5,
		Name:           "goerli",
		ForkVersionHex: "0x00001020",
	}
	Gnosis = Network{
		ChainID:        100,
		Name:           "gnosis",
		ForkVersionHex: "0x00000064",
	}
	Sepolia = Network{
		ChainID:        11155111,
		Name:           "sepolia",
		ForkVersionHex: "0x90000069",
	}
	Ropsten = Network{
		ChainID:        3,
		Name:           "ropsten",
		ForkVersionHex: "0x80000069",
	}
)

var supportedNetworks = []Network{
	Mainnet, Goerli, Gnosis, Sepolia, Ropsten,
}

// ForkVersionToChainID returns the chainID corresponding to the provided fork version.
func ForkVersionToChainID(forkVersion []byte) (int64, error) {
	for _, network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.ForkVersionHex {
			return network.ChainID, nil
		}
	}

	return 0, errors.New("invalid fork version")
}

// ForkVersionToNetwork returns the network name corresponding to the provided fork version.
func ForkVersionToNetwork(forkVersion []byte) (string, error) {
	for _, network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.ForkVersionHex {
			return network.Name, nil
		}
	}

	return "", errors.New("invalid fork version")
}

// NetworkToForkVersion returns the fork version in hex (0x prefixed) corresponding to the network name.
func NetworkToForkVersion(name string) (string, error) {
	for _, network := range supportedNetworks {
		if name == network.Name {
			return network.ForkVersionHex, nil
		}
	}

	return "", errors.New("invalid network name")
}

// NetworkToForkVersionBytes returns the fork version bytes corresponding to the network name.
func NetworkToForkVersionBytes(name string) ([]byte, error) {
	forkVersion, err := NetworkToForkVersion(name)
	if err != nil {
		return nil, err
	}

	b, err := hex.DecodeString(strings.TrimPrefix(forkVersion, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode fork version hex")
	}

	return b, nil
}

// ValidNetwork returns true if the provided network name is a valid one.
func ValidNetwork(name string) bool {
	for _, network := range supportedNetworks {
		if name == network.Name {
			return true
		}
	}

	return false
}
