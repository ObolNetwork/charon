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

package core

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// VerifyEth2SignedData verifies signature associated with given Eth2SignedData.
func VerifyEth2SignedData(ctx context.Context, eth2Cl eth2wrap.Client, data Eth2SignedData, pubkey *bls_sig.PublicKey) error {
	epoch, err := data.Epoch(ctx, eth2Cl)
	if err != nil {
		return err
	}

	sigRoot, err := data.MessageRoot()
	if err != nil {
		return err
	}

	return signing.Verify(ctx, eth2Cl, data.DomainName(), epoch, sigRoot, data.Signature().ToETH2(), pubkey)
}

// Implement Eth2SignedData for VersionedSignedBeaconBlock.

func (VersionedSignedBeaconBlock) DomainName() signing.DomainName {
	return signing.DomainBeaconProposer
}

func (b VersionedSignedBeaconBlock) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := b.VersionedSignedBeaconBlock.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for VersionedSignedBlindedBeaconBlock.

func (VersionedSignedBlindedBeaconBlock) DomainName() signing.DomainName {
	return signing.DomainBeaconProposer
}

func (b VersionedSignedBlindedBeaconBlock) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := b.VersionedSignedBlindedBeaconBlock.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for Attestation.

func (Attestation) DomainName() signing.DomainName {
	return signing.DomainBeaconAttester
}

func (a Attestation) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return a.Attestation.Data.Target.Epoch, nil
}

// Implement Eth2SignedData for SignedVoluntaryExit.

func (SignedVoluntaryExit) DomainName() signing.DomainName {
	return signing.DomainExit
}

func (e SignedVoluntaryExit) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return e.Message.Epoch, nil
}

// Implement Eth2SignedData for VersionedSignedValidatorRegistration.

func (VersionedSignedValidatorRegistration) DomainName() signing.DomainName {
	return signing.DomainApplicationBuilder
}

func (VersionedSignedValidatorRegistration) Epoch(context.Context, eth2wrap.Client) (eth2p0.Epoch, error) {
	// Always use epoch 0 for DomainApplicationBuilder.
	return 0, nil
}

// Implement Eth2SignedData for SignedRandao.

func (SignedRandao) DomainName() signing.DomainName {
	return signing.DomainRandao
}

func (s SignedRandao) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return s.SignedEpoch.Epoch, nil
}

// Implement Eth2SignedData for BeaconCommitteeSelection.

func (BeaconCommitteeSelection) DomainName() signing.DomainName {
	return signing.DomainSelectionProof
}

func (s BeaconCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedAggregateAndProof.

func (SignedAggregateAndProof) DomainName() signing.DomainName {
	return signing.DomainAggregateAndProof
}

func (s SignedAggregateAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Aggregate.Data.Slot)
}

// Implement Eth2SignedData for SignedSyncMessage.

func (SignedSyncMessage) DomainName() signing.DomainName {
	return signing.DomainSyncCommittee
}

func (s SignedSyncMessage) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedSyncContributionAndProof.

func (SignedSyncContributionAndProof) DomainName() signing.DomainName {
	return signing.DomainContributionAndProof
}

func (s SignedSyncContributionAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Contribution.Slot)
}
