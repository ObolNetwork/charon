// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/obolnetwork/charon/app/errors"
)

const Prater = "prater"

// Network contains information about an Ethereum network.
type Network struct {
	// ChainID represents chainID of the network.
	ChainID int64
	// Name represents name of the network.
	Name string
	// GenesisForkVersionHex represents fork version of the network in hex.
	GenesisForkVersionHex string
	// GenesisTimestamp represents genesis timestamp of the network in unix format
	GenesisTimestamp int64
}

var (
	Mainnet = Network{
		ChainID:               1,
		Name:                  "mainnet",
		GenesisForkVersionHex: "0x00000000",
		GenesisTimestamp:      1606824023,
	}
	Goerli = Network{
		ChainID:               5,
		Name:                  "goerli",
		GenesisForkVersionHex: "0x00001020",
		GenesisTimestamp:      1616508000,
	}
	Gnosis = Network{
		ChainID:               100,
		Name:                  "gnosis",
		GenesisForkVersionHex: "0x00000064",
		GenesisTimestamp:      1638993340,
	}
	Sepolia = Network{
		ChainID:               11155111,
		Name:                  "sepolia",
		GenesisForkVersionHex: "0x90000069",
		GenesisTimestamp:      1655733600,
	}
	// Holesky metadata taken from https://github.com/eth-clients/holesky#metadata.
	Holesky = Network{
		ChainID:               17000,
		Name:                  "holesky",
		GenesisForkVersionHex: "0x01017000",
		GenesisTimestamp:      1696000704,
	}
)

var supportedNetworks = []Network{
	Mainnet, Goerli, Gnosis, Sepolia, Holesky,
}

// ForkVersionToChainID returns the chainID corresponding to the provided fork version.
func ForkVersionToChainID(forkVersion []byte) (int64, error) {
	for _, network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.GenesisForkVersionHex {
			return network.ChainID, nil
		}
	}

	return 0, errors.New("invalid fork version")
}

// ForkVersionToNetwork returns the network name corresponding to the provided fork version.
func ForkVersionToNetwork(forkVersion []byte) (string, error) {
	for _, network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.GenesisForkVersionHex {
			return network.Name, nil
		}
	}

	return "", errors.New("invalid fork version")
}

// NetworkToForkVersion returns the fork version in hex (0x prefixed) corresponding to the network name.
func NetworkToForkVersion(name string) (string, error) {
	for _, network := range supportedNetworks {
		if name == network.Name {
			return network.GenesisForkVersionHex, nil
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

func NetworkToGenesisTime(name string) (time.Time, error) {
	for _, network := range supportedNetworks {
		if name == network.Name {
			return time.Unix(network.GenesisTimestamp, 0), nil
		}
	}

	return time.Time{}, errors.New("invalid network name")
}

func ForkVersionToGenesisTime(forkVersion []byte) (time.Time, error) {
	for _, network := range supportedNetworks {
		if fmt.Sprintf("%#x", forkVersion) == network.GenesisForkVersionHex {
			return time.Unix(network.GenesisTimestamp, 0), nil
		}
	}

	return time.Time{}, errors.New("invalid network name")
}

func NetworkFromString(name string) (Network, error) {
	for _, network := range supportedNetworks {
		if name == network.Name {
			return network, nil
		}
	}

	return Network{}, errors.New("invalid network name")
}
