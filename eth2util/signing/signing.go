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
	"fmt"
	"reflect"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
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

// TODO(corevr): Create a function that calculates signing roots for all unsigned eth2 types.
// func UnsignedRoot(ctx context.Context, eth2Cl Eth2Provider, unsigned interface{}) ([32]byte, error) {
//
//}

// VerifySignedData verifies any eth2 signed data signature.
// If it is partially signed, provide the pubshare.
// If it is aggregate signed, provide the group pubkey.
func VerifySignedData(ctx context.Context, eth2Cl Eth2Provider, pubkey *bls_sig.PublicKey,
	eth2SignedType interface{},
) error {
	// eth2util shouldn't import core package, so can't use core.SignedData.
	// To avoid pointer vs non-pointer issues, always get value if pointer is provided.
	if reflect.TypeOf(eth2SignedType).Kind() == reflect.Pointer {
		eth2SignedType = reflect.ValueOf(eth2SignedType).Elem().Interface()
	}

	switch signed := eth2SignedType.(type) {
	case eth2p0.Attestation:
		sigRoot, err := signed.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation data")
		}

		return Verify(ctx, eth2Cl, DomainBeaconAttester, signed.Data.Target.Epoch,
			sigRoot, signed.Signature, pubkey)
	case spec.VersionedSignedBeaconBlock:

		slot, err := signed.Slot()
		if err != nil {
			return err
		}

		// Calculate slot epoch
		epoch, err := epochFromSlot(ctx, eth2Cl, slot)
		if err != nil {
			return err
		}

		sigRoot, err := signed.Root()
		if err != nil {
			return err
		}

		var sig eth2p0.BLSSignature
		switch signed.Version {
		case spec.DataVersionPhase0:
			sig = signed.Phase0.Signature
		case spec.DataVersionAltair:
			sig = signed.Altair.Signature
		case spec.DataVersionBellatrix:
			sig = signed.Bellatrix.Signature
		default:
			return errors.New("unknown version")
		}

		return Verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, sig, pubkey)
	case eth2api.VersionedSignedBlindedBeaconBlock:
		slot, err := signed.Slot()
		if err != nil {
			return err
		}

		// Calculate slot epoch
		epoch, err := epochFromSlot(ctx, eth2Cl, slot)
		if err != nil {
			return err
		}

		sigRoot, err := signed.Root()
		if err != nil {
			return err
		}

		var sig eth2p0.BLSSignature
		switch signed.Version {
		case spec.DataVersionBellatrix:
			sig = signed.Bellatrix.Signature
		default:
			return errors.New("unknown version")
		}

		return Verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, sig, pubkey)
	// case core.Signature:
	// TODO(corver): Refactor randao SignedData to include epoch.
	// return errors.New("randao not supported yet")

	// var epoch eth2p0.Epoch
	//
	// sigRoot, err := eth2util.EpochHashRoot(epoch)
	// if err != nil {
	//	return err
	//}
	//
	// return Verify(ctx, eth2Cl, DomainRandao, epoch, sigRoot, signed.ToETH2(), pubkey)
	case eth2p0.SignedVoluntaryExit:
		sigRoot, err := signed.Message.HashTreeRoot()
		if err != nil {
			return err
		}

		return Verify(ctx, eth2Cl, DomainExit, signed.Message.Epoch, sigRoot,
			signed.Signature, pubkey)
	case eth2api.VersionedSignedValidatorRegistration:
		// TODO: switch to signed.Root() when implemented on go-eth2-client (PR has been raised)
		sigRoot, err := signed.V1.Message.HashTreeRoot()
		if err != nil {
			return err
		}

		return Verify(ctx, eth2Cl, DomainApplicationBuilder, 0, sigRoot,
			signed.V1.Signature, pubkey)
	default:
		return errors.New("unsupported eth2 signed data type", z.Str("type", fmt.Sprintf("%T", eth2SignedType)))
	}
}

// Verify returns an error if the signature doesn't match the eth2 domain signed root.
// TODO(corver): Unexport this once Randao partial signatures contain their epoch.
func Verify(ctx context.Context, eth2Cl Eth2Provider, domain DomainName, epoch eth2p0.Epoch,
	sigRoot [32]byte, sig eth2p0.BLSSignature, pubshare *bls_sig.PublicKey,
) error {
	sigData, err := GetDataRoot(ctx, eth2Cl, domain, epoch, sigRoot)
	if err != nil {
		return err
	}

	var zeroSig eth2p0.BLSSignature
	if sig == zeroSig {
		return errors.New("no signature found")
	}

	// Convert the signature
	s, err := tblsconv.SigFromETH2(sig)
	if err != nil {
		return errors.Wrap(err, "convert signature")
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
