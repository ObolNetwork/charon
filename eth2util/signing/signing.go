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

package signing

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

// DomainName as defined in eth2 spec.
// See "specs/[phase0|altair]/beacon-chain.md#domain-types" in https://github.com/ethereum/consensus-specs.
type DomainName string

const (
	DomainBeaconProposer     DomainName = "DOMAIN_BEACON_PROPOSER"
	DomainBeaconAttester     DomainName = "DOMAIN_BEACON_ATTESTER"
	DomainRandao             DomainName = "DOMAIN_RANDAO"
	DomainExit               DomainName = "DOMAIN_VOLUNTARY_EXIT"
	DomainApplicationBuilder DomainName = "DOMAIN_APPLICATION_BUILDER"
	// DomainDeposit        	         DomainName = "DOMAIN_DEPOSIT"
	// DomainSelectionProof              DomainName = "DOMAIN_SELECTION_PROOF"
	// DomainAggregateAndProof           DomainName = "DOMAIN_AGGREGATE_AND_PROOF"
	// DomainSyncCommittee               DomainName = "DOMAIN_SYNC_COMMITTEE"
	// DomainSyncCommitteeSelectionProof DomainName = "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"
	// DomainContributionAndProof        DomainName = "DOMAIN_CONTRIBUTION_AND_PROOF".
)

// Eth2DomainProvider is the subset of eth2 beacon api provider required to get a signing domain.
type Eth2DomainProvider interface {
	eth2client.SpecProvider
	eth2client.DomainProvider
}

// GetDomain returns the beacon domain for the provided type.
func GetDomain(ctx context.Context, eth2Cl Eth2DomainProvider, name DomainName, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
	// TODO(corver): Remove once https://github.com/attestantio/go-eth2-client/pull/23 is released
	if name == DomainApplicationBuilder {
		// See https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#domain-types
		return eth2Cl.Domain(ctx, eth2p0.DomainType{0, 0, 0, 1}, epoch)
	}

	spec, err := eth2Cl.Spec(ctx)
	if err != nil {
		return eth2p0.Domain{}, err
	}

	domainType, ok := spec[string(name)]
	if !ok {
		return eth2p0.Domain{}, errors.New("domain type not found")
	}

	domainTyped, ok := domainType.(eth2p0.DomainType)
	if !ok {
		return eth2p0.Domain{}, errors.New("invalid domain type")
	}

	return eth2Cl.Domain(ctx, domainTyped, epoch)
}

// GetDataRoot wraps the signing root with the domain and returns signing data hash tree root.
// The result should be identical to what was signed by the VC.
func GetDataRoot(ctx context.Context, eth2Cl Eth2DomainProvider, name DomainName, epoch eth2p0.Epoch, root eth2p0.Root) ([32]byte, error) {
	domain, err := GetDomain(ctx, eth2Cl, name, epoch)
	if err != nil {
		return [32]byte{}, err
	}

	msg, err := (&eth2p0.SigningData{ObjectRoot: root, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal signing data")
	}

	return msg, nil
}
