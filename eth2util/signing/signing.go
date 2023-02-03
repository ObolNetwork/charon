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

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/eth2util"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
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
		return errors.Wrap(err, "cannot get hash root of slot")
	}

	rawKey, err := pubkey.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "cannot serialize public key")
	}

	return Verify(ctx, eth2Cl, DomainSelectionProof, epoch, sigRoot, agg.SelectionProof, rawKey)
}

// Verify returns an error if the signature doesn't match the eth2 domain signed root.
func Verify(ctx context.Context, eth2Cl eth2wrap.Client, domain DomainName, epoch eth2p0.Epoch, sigRoot eth2p0.Root,
	signature eth2p0.BLSSignature, pubkey []byte,
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

	if len(pubkey) != len(tblsv2.PublicKey{}) {
		return errors.New("invalid length", z.Str("pubkey", hex.EncodeToString(pubkey)))
	}

	span.AddEvent("tbls.Verify")

	return tblsv2.Verify(*(*tblsv2.PublicKey)(pubkey), sigData[:], tblsv2.Signature(signature))
}
