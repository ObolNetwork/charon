// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const Prater = "prater"

// Network contains information about an Ethereum network.
type Network struct {
	// ChainID represents chainID of the network.
	ChainID uint64
	// Name represents name of the network.
	Name string
	// GenesisForkVersionHex represents fork version of the network in hex.
	GenesisForkVersionHex string
	// GenesisTimestamp represents genesis timestamp of the network in unix format
	GenesisTimestamp int64
	// CapellaHardFork represents capella fork version, used for computing domains for signatures
	CapellaHardFork string
	// GenesisValidatorsRootHex represents the genesis validators root of the network in hex, used for
	// computing the voluntary exit domain without a beacon node. Empty when unknown.
	GenesisValidatorsRootHex string
	// SlotDuration represents slot duration in seconds
	SlotDuration uint64
	// GloasHardForkTimestamp represents the wall-clock time at which the gloas hard fork
	// activates on the network, in unix seconds. Zero when the fork is not scheduled.
	GloasHardForkTimestamp int64
}

// IsNonZero checks if each field in this struct is not equal to its zero value.
func (n Network) IsNonZero() bool {
	return n.Name != "" && n.ChainID != 0 && n.GenesisTimestamp != 0 && n.GenesisForkVersionHex != ""
}

// Pre-defined network configurations.
var (
	Mainnet = Network{
		ChainID:                  1,
		Name:                     "mainnet",
		GenesisForkVersionHex:    "0x00000000",
		GenesisTimestamp:         1606824023,
		CapellaHardFork:          "0x03000000",
		GenesisValidatorsRootHex: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
		SlotDuration:             12,
	}
	Goerli = Network{
		ChainID:               5,
		Name:                  "goerli",
		GenesisForkVersionHex: "0x00001020",
		GenesisTimestamp:      1616508000,
		CapellaHardFork:       "0x03001020",
		SlotDuration:          12,
	}
	Gnosis = Network{
		ChainID:                  100,
		Name:                     "gnosis",
		GenesisForkVersionHex:    "0x00000064",
		GenesisTimestamp:         1638993340,
		CapellaHardFork:          "0x03000064",
		GenesisValidatorsRootHex: "0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
		SlotDuration:             5,
	}
	Chiado = Network{
		ChainID:                  10200,
		Name:                     "chiado",
		GenesisForkVersionHex:    "0x0000006f",
		GenesisTimestamp:         1665396300,
		CapellaHardFork:          "0x0300006f",
		GenesisValidatorsRootHex: "0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e",
		SlotDuration:             5,
	}
	Sepolia = Network{
		ChainID:                  11155111,
		Name:                     "sepolia",
		GenesisForkVersionHex:    "0x90000069",
		GenesisTimestamp:         1655733600,
		CapellaHardFork:          "0x90000072",
		GenesisValidatorsRootHex: "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
		SlotDuration:             12,
	}
	// Hoodi metadata taken from https://github.com/eth-clients/hoodi/#metadata.
	Hoodi = Network{
		ChainID:                  560048,
		Name:                     "hoodi",
		GenesisForkVersionHex:    "0x10000910",
		GenesisTimestamp:         1742213400,
		CapellaHardFork:          "0x40000910",
		GenesisValidatorsRootHex: "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
		SlotDuration:             12,
	}
)

var (
	networksMu        sync.Mutex
	supportedNetworks = []Network{
		Mainnet, Goerli, Gnosis, Chiado, Sepolia, Hoodi,
	}
)

// AddTestNetwork adds given network to list of supported networks.
func AddTestNetwork(network Network) {
	networksMu.Lock()
	defer networksMu.Unlock()

	supportedNetworks = append(supportedNetworks, network)
}

// networkFromName returns network from the given network name from list of supported networks.
func networkFromName(name string) (Network, error) {
	networksMu.Lock()
	defer networksMu.Unlock()

	for _, network := range supportedNetworks {
		if name == network.Name {
			return network, nil
		}
	}

	return Network{}, errors.New("invalid network name", z.Str("network", name))
}

// networkFromForkVersion returns network from the given fork version from the list of supported networks.
func networkFromForkVersion(forkVersion string) (Network, error) {
	networksMu.Lock()
	defer networksMu.Unlock()

	for _, network := range supportedNetworks {
		if forkVersion == network.GenesisForkVersionHex {
			return network, nil
		}
	}

	return Network{}, errors.New("invalid fork version", z.Str("fork_version", forkVersion))
}

// ForkVersionToChainID returns the chainID corresponding to the provided fork version.
func ForkVersionToChainID(forkVersion []byte) (uint64, error) {
	network, err := networkFromForkVersion(fmt.Sprintf("%#x", forkVersion))
	if err != nil {
		return 0, err
	}

	return network.ChainID, nil
}

// GloasActive returns true if the network of the provided fork version has the gloas
// hard fork scheduled and active at the given time. It returns false for unknown networks.
func GloasActive(forkVersion []byte, now time.Time) bool {
	network, err := networkFromForkVersion(fmt.Sprintf("%#x", forkVersion))
	if err != nil {
		return false
	}

	return network.GloasHardForkTimestamp != 0 && now.Unix() >= network.GloasHardForkTimestamp
}

// ForkVersionToNetwork returns the network name corresponding to the provided fork version.
func ForkVersionToNetwork(forkVersion []byte) (string, error) {
	network, err := networkFromForkVersion(fmt.Sprintf("%#x", forkVersion))
	if err != nil {
		return "", err
	}

	return network.Name, nil
}

// NetworkToForkVersion returns the fork version in hex (0x prefixed) corresponding to the network name.
func NetworkToForkVersion(name string) (string, error) {
	network, err := networkFromName(name)
	if err != nil {
		return "", err
	}

	return network.GenesisForkVersionHex, nil
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
	_, err := networkFromName(name)
	return err == nil
}

func NetworkToGenesisTime(name string) (time.Time, error) {
	network, err := networkFromName(name)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(network.GenesisTimestamp, 0), nil
}

func NetworkToSlotDuration(name string) (uint64, error) {
	network, err := networkFromName(name)
	if err != nil {
		return 0, err
	}

	return network.SlotDuration, nil
}

func ForkVersionToGenesisTime(forkVersion []byte) (time.Time, error) {
	network, err := networkFromForkVersion(fmt.Sprintf("%#x", forkVersion))
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(network.GenesisTimestamp, 0), nil
}
