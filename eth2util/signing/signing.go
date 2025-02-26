// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package signing

import (
	"context"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/tbls"
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
	DomainBlobSidecar                 DomainName = "DOMAIN_BLOB_SIDECAR"
)

// GetDomain returns the beacon domain for the provided type.
func GetDomain(ctx context.Context, eth2Cl eth2wrap.Client, name DomainName, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
	resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return eth2p0.Domain{}, err
	}
	spec := resp.Data

	domainType, ok := spec[string(name)]
	if !ok {
		return eth2p0.Domain{}, errors.New("domain type not found")
	}

	domainTyped, ok := domainType.(eth2p0.DomainType)
	if !ok {
		return eth2p0.Domain{}, errors.New("invalid domain type")
	}

	// Domain needs to be genesis one for DomainApplicationBuilder
	if name == DomainApplicationBuilder {
		return eth2Cl.GenesisDomain(ctx, domainTyped)
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

// VerifyAggregateAndProofSelection verifies the eth2p0.AggregateAndProof with the provided pubkey.
// Refer get_slot_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection.
func VerifyAggregateAndProofSelection(ctx context.Context, eth2Cl eth2wrap.Client, pubkey tbls.PublicKey, agg *eth2p0.AggregateAndProof) error {
	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, agg.Aggregate.Data.Slot)
	if err != nil {
		return err
	}

	sigRoot, err := eth2util.SlotHashRoot(agg.Aggregate.Data.Slot)
	if err != nil {
		return errors.Wrap(err, "cannot get hash root of slot")
	}

	return Verify(ctx, eth2Cl, DomainSelectionProof, epoch, sigRoot, agg.SelectionProof, pubkey)
}

// VerifyAggregateAndProofSelectionV2 verifies the eth2p0.AggregateAndProof with the provided pubkey.
// Refer get_slot_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection.
func VerifyAggregateAndProofSelectionV2(ctx context.Context, eth2Cl eth2wrap.Client, pubkey tbls.PublicKey, agg *eth2spec.VersionedSignedAggregateAndProof) error {
	slot, err := agg.Slot()
	if err != nil {
		return err
	}

	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigRoot, err := eth2util.SlotHashRoot(slot)
	if err != nil {
		return errors.Wrap(err, "cannot get hash root of slot")
	}

	selectionProof, err := agg.SelectionProof()
	if err != nil {
		return err
	}

	return Verify(ctx, eth2Cl, DomainSelectionProof, epoch, sigRoot, selectionProof, pubkey)
}

// Verify returns an error if the signature doesn't match the eth2 domain signed root.
func Verify(ctx context.Context, eth2Cl eth2wrap.Client, domain DomainName, epoch eth2p0.Epoch, sigRoot eth2p0.Root,
	signature eth2p0.BLSSignature, pubkey tbls.PublicKey,
) error {
	ctx, span := tracer.Start(ctx, "eth2util.Verify")
	defer span.End()

	sigData, err := GetDataRoot(ctx, eth2Cl, domain, epoch, sigRoot)
	if err != nil {
		return err
	}

	var zeroSig eth2p0.BLSSignature
	if signature == zeroSig {
		return errors.New("no signature found")
	}

	span.AddEvent("tbls.Verify")

	return tbls.Verify(pubkey, sigData[:], tbls.Signature(signature))
}
