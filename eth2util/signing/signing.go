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

	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

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

// VerifyAggregateAndProofSelection verifies the eth2p0.AggregateAndProof with the provided pubkey.
// Refer get_slot_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#aggregation-selection.
func VerifyAggregateAndProofSelection(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, agg *eth2p0.AggregateAndProof) error {
	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, agg.Aggregate.Data.Slot)
	if err != nil {
		return err
	}

	sigRoot, err := eth2util.SlotHashRoot(agg.Aggregate.Data.Slot)
	if err != nil {
		return err
	}

	return Verify(ctx, eth2Cl, DomainSelectionProof, epoch, sigRoot, agg.SelectionProof, pubkey)
}

// VerifySyncContributionAndProof verifies the altair.SignedContributionAndProof with the provided pubkey.
// Refer get_contribution_and_proof_signature from https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#broadcast-sync-committee-contribution.
func VerifySyncContributionAndProof(ctx context.Context, eth2Cl eth2wrap.Client, pubkey *bls_sig.PublicKey, contrib *altair.SignedContributionAndProof) error {
	epoch, err := eth2util.EpochFromSlot(ctx, eth2Cl, contrib.Message.Contribution.Slot)
	if err != nil {
		return err
	}

	sigRoot, err := contrib.Message.HashTreeRoot()
	if err != nil {
		return err
	}

	return Verify(ctx, eth2Cl, DomainContributionAndProof, epoch, sigRoot, contrib.Signature, pubkey)
}

// Verify returns an error if the signature doesn't match the eth2 domain signed root.
func Verify(ctx context.Context, eth2Cl eth2wrap.Client, domain DomainName, epoch eth2p0.Epoch, sigRoot eth2p0.Root,
	signature eth2p0.BLSSignature, pubkey *bls_sig.PublicKey,
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

	// Convert the signature
	s, err := sigFromETH2(signature)
	if err != nil {
		return errors.Wrap(err, "convert signature")
	}

	span.AddEvent("tbls.Verify")
	ok, err := tbls.Verify(pubkey, sigData[:], s)
	if err != nil {
		return err
	} else if !ok {
		return errors.New("invalid signature")
	}

	return nil
}

// sigFromETH2 converts an eth2 phase0 bls signature into a kryptology bls signature.
func sigFromETH2(sig eth2p0.BLSSignature) (*bls_sig.Signature, error) {
	point, err := new(bls12381.G2).FromCompressed((*[96]byte)(sig[:]))
	if err != nil {
		return nil, errors.Wrap(err, "uncompress sig")
	}

	return &bls_sig.Signature{Value: *point}, nil
}
