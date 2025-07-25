// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"context"
	"encoding/hex"
	"strings"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// CapellaFork maps generic fork hashes to their specific Capella hardfork
// values.
func CapellaFork(forkHash string) (string, error) {
	networksMu.Lock()
	defer networksMu.Unlock()

	for _, n := range supportedNetworks {
		if n.GenesisForkVersionHex == forkHash {
			return n.CapellaHardFork, nil
		}
	}

	return "", errors.New("no capella fork for specified fork")
}

type forkDataType struct {
	CurrentVersion        [4]byte
	GenesisValidatorsRoot [32]byte
}

func (e forkDataType) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(e)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (e forkDataType) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(e)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (e forkDataType) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'CurrentVersion'
	hh.PutBytes(e.CurrentVersion[:])

	// Field (1) 'GenesisValidatorsRoot'
	hh.PutBytes(e.GenesisValidatorsRoot[:])

	hh.Merkleize(indx)

	return nil
}

// ComputeDomain computes the domain for a given domainType, genesisValidatorRoot at the specified fork hash.
func ComputeDomain(forkHash string, domainType eth2p0.DomainType, genesisValidatorRoot eth2p0.Root) (eth2p0.Domain, error) {
	_, err := hex.DecodeString(strings.TrimPrefix(forkHash, "0x"))
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "malformed fork hash")
	}

	cfork, err := CapellaFork(forkHash)
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "invalid fork hash")
	}

	cforkHex, err := hex.DecodeString(strings.TrimPrefix(cfork, "0x"))
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "capella fork hash hex")
	}

	rawFdt := forkDataType{GenesisValidatorsRoot: genesisValidatorRoot, CurrentVersion: [4]byte(cforkHex)}

	fdt, err := rawFdt.HashTreeRoot()
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "fork data type hash tree root")
	}

	var domain []byte

	domain = append(domain, domainType[:]...)
	domain = append(domain, fdt[:28]...)

	return eth2p0.Domain(domain), nil
}

// CapellaDomain returns the Capella signature domain, calculating it given the fork hash string.
func CapellaDomain(
	ctx context.Context,
	forkHash string,
	specProvider eth2client.SpecProvider,
	genesisProvider eth2client.GenesisProvider,
) (eth2p0.Domain, error) {
	rawSpec, err := specProvider.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "fetch spec")
	}

	genesis, err := genesisProvider.Genesis(ctx, &eth2api.GenesisOpts{})
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "fetch genesis")
	}

	spec := rawSpec.Data

	domainType, ok := spec["DOMAIN_VOLUNTARY_EXIT"]
	if !ok {
		return eth2p0.Domain{}, errors.New("domain type not found in spec")
	}

	domainTyped, ok := domainType.(eth2p0.DomainType)
	if !ok {
		return [32]byte{}, errors.New("invalid domain type")
	}

	domain, err := ComputeDomain(forkHash, domainTyped, genesis.Data.GenesisValidatorsRoot)
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "compute domain")
	}

	return domain, nil
}
