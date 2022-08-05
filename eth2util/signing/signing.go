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
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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

// Eth2Provider is the subset of eth2 beacon api provider required to get a signing domain.
type Eth2Provider interface {
	eth2client.DomainProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
}

// GetDomain returns the beacon domain for the provided type.
func GetDomain(ctx context.Context, eth2Cl Eth2Provider, name DomainName, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
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

// GetRegistrationDomain returns a non-standard domain for validator builder registration.
// See https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#signing.
func GetRegistrationDomain() (eth2p0.Domain, error) {
	root, err := (&eth2p0.ForkData{}).HashTreeRoot() // Zero fork data
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "hash fork data")
	}

	// See https://github.com/ethereum/builder-specs/blob/main/specs/builder.md#domain-types.
	registrationDomainType := eth2p0.DomainType{0, 0, 0, 1}

	var domain eth2p0.Domain
	copy(domain[0:], registrationDomainType[:])
	copy(domain[4:], root[:])

	return domain, nil
}

// GetDataRoot wraps the signing root with the domain and returns signing data hash tree root.
// The result should be identical to what was signed by the VC.
func GetDataRoot(ctx context.Context, eth2Cl Eth2Provider, name DomainName, epoch eth2p0.Epoch, root eth2p0.Root) ([32]byte, error) {
	var (
		domain eth2p0.Domain
		err    error
	)
	if name == DomainApplicationBuilder {
		// Builder registration uses non-standard domain.
		domain, err = GetRegistrationDomain()
		if err != nil {
			return [32]byte{}, err
		}
	} else {
		domain, err = GetDomain(ctx, eth2Cl, name, epoch)
		if err != nil {
			return [32]byte{}, err
		}
	}

	msg, err := (&eth2p0.SigningData{ObjectRoot: root, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal signing data")
	}

	return msg, nil
}

// NewVerifyFunc returns partial signature verification function which verifies given ParSignedData according to Duty Type.
//nolint:gocognit
func NewVerifyFunc(eth2Cl Eth2Provider) func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error {
	return func(ctx context.Context, duty core.Duty, pubkey core.PubKey, parSig core.ParSignedData) error {
		switch duty.Type {
		case core.DutyAttester:
			att, ok := parSig.SignedData.(core.Attestation)
			if !ok {
				return errors.New("invalid attestation")
			}

			sigRoot, err := att.Data.HashTreeRoot()
			if err != nil {
				return errors.Wrap(err, "hash attestation data")
			}

			return verify(ctx, eth2Cl, DomainBeaconAttester, att.Data.Target.Epoch, sigRoot, att.Attestation.Signature, pubkey)
		case core.DutyProposer:
			block, ok := parSig.SignedData.(core.VersionedSignedBeaconBlock)
			if !ok {
				return errors.New("invalid block")
			}

			// Calculate slot epoch
			epoch, err := epochFromSlot(ctx, eth2Cl, eth2p0.Slot(duty.Slot))
			if err != nil {
				return err
			}

			sigRoot, err := block.Root()
			if err != nil {
				return err
			}

			return verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, block.Signature().ToETH2(), pubkey)
		case core.DutyBuilderProposer:
			blindedBlock, ok := parSig.SignedData.(core.VersionedSignedBlindedBeaconBlock)
			if !ok {
				return errors.New("invalid blinded block")
			}

			// Calculate slot epoch
			epoch, err := epochFromSlot(ctx, eth2Cl, eth2p0.Slot(duty.Slot))
			if err != nil {
				return err
			}

			sigRoot, err := blindedBlock.Root()
			if err != nil {
				return err
			}

			return verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, blindedBlock.Signature().ToETH2(), pubkey)
		case core.DutyRandao:
			randao, ok := parSig.SignedData.(core.Signature)
			if !ok {
				return errors.New("invalid randao")
			}

			// Calculate slot epoch
			epoch, err := epochFromSlot(ctx, eth2Cl, eth2p0.Slot(duty.Slot))
			if err != nil {
				return err
			}

			sigRoot, err := eth2util.EpochHashRoot(epoch)
			if err != nil {
				return err
			}

			return verify(ctx, eth2Cl, DomainRandao, epoch, sigRoot, randao.ToETH2(), pubkey)
		case core.DutyExit:
			exit, ok := parSig.SignedData.(core.SignedVoluntaryExit)
			if !ok {
				return errors.New("invalid voluntary exit")
			}

			sigRoot, err := exit.Message.HashTreeRoot()
			if err != nil {
				return err
			}

			return verify(ctx, eth2Cl, DomainExit, exit.Message.Epoch, sigRoot, exit.SignedVoluntaryExit.Signature, pubkey)
		default:
			return errors.New("invalid duty type")
		}
	}
}

func verify(ctx context.Context, eth2Cl Eth2Provider, domain DomainName, epoch eth2p0.Epoch, sigRoot [32]byte, sig eth2p0.BLSSignature, pubkey core.PubKey) error {
	sigData, err := GetDataRoot(ctx, eth2Cl, domain, epoch, sigRoot)
	if err != nil {
		return err
	}

	// Convert the signature
	s, err := tblsconv.SigFromETH2(sig)
	if err != nil {
		return errors.Wrap(err, "convert signature")
	}

	// Verify using public share
	pubshare, err := tblsconv.KeyFromCore(pubkey)
	if err != nil {
		return err
	}

	ok, err := tbls.Verify(pubshare, sigData[:], s)
	if err != nil {
		return err
	} else if !ok {
		return errors.New("invalid signature")
	}

	return nil
}

func epochFromSlot(ctx context.Context, eth2Cl Eth2Provider, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "getting slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}
