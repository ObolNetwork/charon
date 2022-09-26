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

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// DomainName as defined in eth2 spec.
// See "specs/[phase0|altair]/beacon-chain.md#domain-types" in https://github.com/ethereum/consensus-specs.
type DomainName string

const (
	DomainBeaconProposer              DomainName = "DOMAIN_BEACON_PROPOSER"
	DomainBeaconAttester              DomainName = "DOMAIN_BEACON_ATTESTER"
	DomainRandao                      DomainName = "DOMAIN_RANDAO"
	DomainExit                        DomainName = "DOMAIN_VOLUNTARY_EXIT"
	DomainApplicationBuilder          DomainName = "DOMAIN_APPLICATION_BUILDER"
	DomainSelectionProof              DomainName = "DOMAIN_SELECTION_PROOF"
	DomainAggregateAndProof           DomainName = "DOMAIN_AGGREGATE_AND_PROOF"
	DomainSyncCommittee               DomainName = "DOMAIN_SYNC_COMMITTEE"
	DomainSyncCommitteeSelectionProof DomainName = "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"
	DomainContributionAndProof        DomainName = "DOMAIN_CONTRIBUTION_AND_PROOF"
	DomainDeposit                     DomainName = "DOMAIN_DEPOSIT"
)

// GetDomain returns the beacon domain for the provided type.
func GetDomain(ctx context.Context, eth2Cl eth2wrap.Client, name DomainName, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
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
func GetDataRoot(ctx context.Context, eth2Cl eth2wrap.Client, name DomainName, epoch eth2p0.Epoch, root eth2p0.Root) ([32]byte, error) {
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

// TODO(corevr): Create a function that calculates signing roots for all unsigned eth2 types.
// func UnsignedRoot(ctx context.Context, eth2Cl eth2wrap.Client, unsigned interface{}) ([32]byte, error) {
//
//}

func VerifyAttestation(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, att *eth2p0.Attestation) error {
	sigRoot, err := att.Data.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash attestation data")
	}

	return verify(ctx, eth2Cl, DomainBeaconAttester, att.Data.Target.Epoch, sigRoot, att.Signature, pubkey)
}

func VerifyBlock(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, block *spec.VersionedSignedBeaconBlock) error {
	slot, err := block.Slot()
	if err != nil {
		return err
	}

	// Calculate slot epoch
	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigRoot, err := block.Root()
	if err != nil {
		return err
	}

	var sig eth2p0.BLSSignature
	switch block.Version {
	case spec.DataVersionPhase0:
		sig = block.Phase0.Signature
	case spec.DataVersionAltair:
		sig = block.Altair.Signature
	case spec.DataVersionBellatrix:
		sig = block.Bellatrix.Signature
	default:
		return errors.New("unknown version")
	}

	return verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, sig, pubkey)
}

func VerifyBlindedBlock(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
	slot, err := block.Slot()
	if err != nil {
		return err
	}

	// Calculate slot epoch
	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigRoot, err := block.Root()
	if err != nil {
		return err
	}

	var sig eth2p0.BLSSignature
	switch block.Version {
	case spec.DataVersionBellatrix:
		sig = block.Bellatrix.Signature
	default:
		return errors.New("unknown version")
	}

	return verify(ctx, eth2Cl, DomainBeaconProposer, epoch, sigRoot, sig, pubkey)
}

func VerifyRandao(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, randao eth2util.SignedEpoch) error {
	sigRoot, err := randao.HashTreeRoot()
	if err != nil {
		return err
	}

	return verify(ctx, eth2Cl, DomainRandao, randao.Epoch, sigRoot, randao.Signature, pubkey)
}

func VerifyVoluntaryExit(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, exit *eth2p0.SignedVoluntaryExit) error {
	sigRoot, err := exit.Message.HashTreeRoot()
	if err != nil {
		return err
	}

	return verify(ctx, eth2Cl, DomainExit, exit.Message.Epoch, sigRoot, exit.Signature, pubkey)
}

func VerifyValidatorRegistration(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, reg *eth2api.VersionedSignedValidatorRegistration) error {
	sigRoot, err := reg.Root()
	if err != nil {
		return err
	}

	// Always use epoch 0 for DomainApplicationBuilder.
	return verify(ctx, eth2Cl, DomainApplicationBuilder, 0, sigRoot, reg.V1.Signature, pubkey)
}

func VerifyBeaconCommitteeSubscription(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, sub *eth2exp.BeaconCommitteeSubscription) error {
	epoch, err := epochFromSlot(ctx, eth2Cl, sub.Slot)
	if err != nil {
		return err
	}

	sigRoot, err := eth2util.SlotHashRoot(sub.Slot)
	if err != nil {
		return err
	}

	return verify(ctx, eth2Cl, DomainSelectionProof, epoch, sigRoot, sub.SlotSignature, pubkey)
}

func VerifyAggregateAndProof(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, agg *eth2p0.SignedAggregateAndProof) error {
	epoch, err := epochFromSlot(ctx, eth2Cl, agg.Message.Aggregate.Data.Slot)
	if err != nil {
		return err
	}

	sigRoot, err := agg.Message.HashTreeRoot()
	if err != nil {
		return err
	}

	return verify(ctx, eth2Cl, DomainAggregateAndProof, epoch, sigRoot, agg.Signature, pubkey)
}

// verify returns an error if the signature doesn't match the eth2 domain signed root.
func verify(ctx context.Context, eth2Cl eth2wrap.Client, domain DomainName, epoch eth2p0.Epoch,
	sigRoot [32]byte, sig eth2p0.BLSSignature, pubshare *bls_sig.PublicKey,
) error {
	ctx, span := tracer.Start(ctx, "eth2util.verify")
	defer span.End()

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

	span.AddEvent("tbls.Verify")
	ok, err := tbls.Verify(pubshare, sigData[:], s)
	if err != nil {
		return err
	} else if !ok {
		return errors.New("invalid signature")
	}

	return nil
}

func epochFromSlot(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "getting slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}
