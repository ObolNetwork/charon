// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

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
	// Slot duration
	SlotDuration time.Duration
	// Number of slots per epoch
	SlotsPerEpoch uint64
}

// EpochSlot converts an epoch number to its first slot number.
func (n Network) EpochSlot(epoch eth2p0.Epoch) eth2p0.Slot {
	return eth2p0.Slot(epoch) * eth2p0.Slot(n.SlotsPerEpoch)
}

// SlotEpoch converts a slot number to its epoch number.
func (n Network) SlotEpoch(slot eth2p0.Slot) eth2p0.Epoch {
	return eth2p0.Epoch(slot) / eth2p0.Epoch(n.SlotsPerEpoch)
}

// GetGenesisTimestamp returns the genesis timestamp of the network as time.Time.
func (n Network) GetGenesisTimestamp() time.Time {
	return time.Unix(n.GenesisTimestamp, 0)
}

// IsNonZero checks if each field in this struct is not equal to its zero value.
func (n Network) IsNonZero() bool {
	return n.Name != "" && n.ChainID != 0 && n.GenesisTimestamp != 0 && n.GenesisForkVersionHex != ""
}

// Pre-defined network configurations.
var (
	Mainnet = Network{
		ChainID:               1,
		Name:                  "mainnet",
		GenesisForkVersionHex: "0x00000000",
		GenesisTimestamp:      1606824023,
		CapellaHardFork:       "0x03000000",
		SlotDuration:          12 * time.Second,
		SlotsPerEpoch:         32,
	}
	Goerli = Network{
		ChainID:               5,
		Name:                  "goerli",
		GenesisForkVersionHex: "0x00001020",
		GenesisTimestamp:      1616508000,
		CapellaHardFork:       "0x03001020",
		SlotDuration:          12 * time.Second,
		SlotsPerEpoch:         32,
	}
	Gnosis = Network{
		ChainID:               100,
		Name:                  "gnosis",
		GenesisForkVersionHex: "0x00000064",
		GenesisTimestamp:      1638993340,
		CapellaHardFork:       "0x03000064",
		SlotDuration:          5 * time.Second,
		SlotsPerEpoch:         16,
	}
	Chiado = Network{
		ChainID:               10200,
		Name:                  "chiado",
		GenesisForkVersionHex: "0x0000006f",
		GenesisTimestamp:      1665396300,
		CapellaHardFork:       "0x0300006f",
		SlotDuration:          5 * time.Second,
		SlotsPerEpoch:         16,
	}
	Sepolia = Network{
		ChainID:               11155111,
		Name:                  "sepolia",
		GenesisForkVersionHex: "0x90000069",
		GenesisTimestamp:      1655733600,
		CapellaHardFork:       "0x90000072",
		SlotDuration:          12 * time.Second,
		SlotsPerEpoch:         32,
	}
	// Holesky metadata taken from https://github.com/eth-clients/holesky#metadata.
	Holesky = Network{
		ChainID:               17000,
		Name:                  "holesky",
		GenesisForkVersionHex: "0x01017000",
		GenesisTimestamp:      1696000704,
		CapellaHardFork:       "0x04017000",
		SlotDuration:          12 * time.Second,
		SlotsPerEpoch:         32,
	}
	// Hoodi metadata taken from https://github.com/eth-clients/hoodi/#metadata.
	Hoodi = Network{
		ChainID:               560048,
		Name:                  "hoodi",
		GenesisForkVersionHex: "0x10000910",
		GenesisTimestamp:      1742213400,
		CapellaHardFork:       "0x40000910",
		SlotDuration:          12 * time.Second,
		SlotsPerEpoch:         32,
	}
)

var (
	networksMu        sync.RWMutex
	currentNetwork    *Network
	supportedNetworks = []Network{
		Mainnet, Goerli, Gnosis, Chiado, Sepolia, Holesky, Hoodi,
	}
)

// SetCurrentNetwork sets the current network to the given network.
func SetCurrentNetwork(forkVersion []byte) error {
	networksMu.Lock()
	defer networksMu.Unlock()

	if currentNetwork != nil {
		return nil
	}

	forkHex := fmt.Sprintf("%#x", forkVersion)
	var network *Network

	for _, n := range supportedNetworks {
		if forkHex == n.GenesisForkVersionHex {
			network = &n
			break
		}
	}

	if network == nil {
		return errors.New("invalid network name", z.Str("network", forkHex))
	}

	currentNetwork = network

	return nil
}

// SetCustomNetworkForTest is used for testing purposes to override the current network.
func SetCustomNetworkForTest(network *Network) {
	networksMu.Lock()
	defer networksMu.Unlock()

	currentNetwork = network
}

// CurrentNetwork returns the current network.
func CurrentNetwork() *Network {
	networksMu.RLock()
	defer networksMu.RUnlock()

	if currentNetwork == nil {
		panic("current network is not set")
	}

	return currentNetwork
}

// AddTestNetwork adds given network to list of supported networks.
func AddTestNetwork(network Network) {
	networksMu.Lock()
	defer networksMu.Unlock()

	supportedNetworks = append(supportedNetworks, network)
}

// networkFromName returns network from the given network name from list of supported networks.
func networkFromName(name string) (Network, error) {
	networksMu.RLock()
	defer networksMu.RUnlock()

	for _, network := range supportedNetworks {
		if name == network.Name {
			return network, nil
		}
	}

	return Network{}, errors.New("invalid network name", z.Str("network", name))
}

// networkFromForkVersion returns network from the given fork version from the list of supported networks.
func networkFromForkVersion(forkVersion string) (Network, error) {
	networksMu.RLock()
	defer networksMu.RUnlock()

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

func ForkVersionToGenesisTime(forkVersion []byte) (time.Time, error) {
	network, err := networkFromForkVersion(fmt.Sprintf("%#x", forkVersion))
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(network.GenesisTimestamp, 0), nil
}
