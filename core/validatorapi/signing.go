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

package validatorapi

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// DomainName as defined in eth2 spec.
// See "specs/[phase0|altair]/beacon-chain.md#domain-types" in https://github.com/ethereum/consensus-specs.
type DomainName string

const (
	DomainBeaconProposer DomainName = "DOMAIN_BEACON_PROPOSER"
	DomainBeaconAttester DomainName = "DOMAIN_BEACON_ATTESTER"
	DomainRandao         DomainName = "DOMAIN_RANDAO"
	// DomainDeposit                     DomainName = "DOMAIN_DEPOSIT"
	// DomainVoluntaryExit               DomainName = "DOMAIN_VOLUNTARY_EXIT"
	// DomainSelectionProof              DomainName = "DOMAIN_SELECTION_PROOF"
	// DomainAggregateAndProof           DomainName = "DOMAIN_AGGREGATE_AND_PROOF"
	// DomainSyncCommittee               DomainName = "DOMAIN_SYNC_COMMITTEE"
	// DomainSyncCommitteeSelectionProof DomainName = "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"
	// DomainContributionAndProof        DomainName = "DOMAIN_CONTRIBUTION_AND_PROOF".
)

// dutyDomain maps domains to duties.
var dutyDomain = map[core.DutyType]DomainName{
	core.DutyAttester: DomainBeaconAttester,
	core.DutyProposer: DomainBeaconProposer,
	core.DutyRandao:   DomainRandao,
}

// Eth2DomainProvider is the subset of eth2 beacon api provider required to get a signing domain.
type Eth2DomainProvider interface {
	eth2client.SpecProvider
	eth2client.DomainProvider
}

// GetDomain returns the beacon domain for the provided type.
func GetDomain(ctx context.Context, eth2Cl Eth2DomainProvider, name DomainName, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
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

// prepSigningData wraps the signing root with the domain and returns hash tree root to sign.
// The result should be identical to what was signed by the VC.
func prepSigningData(ctx context.Context, eth2Cl eth2Provider, typ core.DutyType, epoch eth2p0.Epoch, root eth2p0.Root) ([32]byte, error) {
	domain, err := GetDomain(ctx, eth2Cl, dutyDomain[typ], epoch)
	if err != nil {
		return [32]byte{}, err
	}

	msg, err := (&eth2p0.SigningData{ObjectRoot: root, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal signing data")
	}

	return msg, nil
}
