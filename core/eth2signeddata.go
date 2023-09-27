// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

var (
	_ Eth2SignedData = VersionedSignedBeaconBlock{}
	_ Eth2SignedData = Attestation{}
	_ Eth2SignedData = SignedVoluntaryExit{}
	_ Eth2SignedData = VersionedSignedBlindedBeaconBlock{}
	_ Eth2SignedData = VersionedSignedValidatorRegistration{}
	_ Eth2SignedData = SignedRandao{}
	_ Eth2SignedData = BeaconCommitteeSelection{}
	_ Eth2SignedData = SignedAggregateAndProof{}
	_ Eth2SignedData = SignedSyncMessage{}
	_ Eth2SignedData = SignedSyncContributionAndProof{}
	_ Eth2SignedData = SyncCommitteeSelection{}
)

// VerifyEth2SignedData verifies signature associated with given Eth2SignedData.
func VerifyEth2SignedData(ctx context.Context, eth2Cl eth2wrap.Client, data Eth2SignedData, pubkey tbls.PublicKey) error {
	epoch, err := data.Epoch(ctx, eth2Cl)
	if err != nil {
		return err
	}

	sigs := data.Signatures()
	sigRoots, err := data.MessageRoots()
	if err != nil {
		return err
	}
	domainNames := data.DomainNames()

	// TODO(xenowits): Figure out a correct way to deal with signed objects with multiple domain names.
	// At the time of writing, only deneb beacon blocks have more than 1 domain (proposal, blob sidecar).
	domain0 := domainNames[0]
	err = signing.Verify(ctx, eth2Cl, domain0, epoch, sigRoots[0], sigs[0].ToETH2(), pubkey)
	if err != nil {
		return errors.Wrap(err, "verify signed data", z.Str("domain", string(domainNames[0])))
	}

	if len(domainNames) > 1 {
		// Verify signed blob sidecars
		domain1 := domainNames[1]
		for i, sig := range sigs {
			err = signing.Verify(ctx, eth2Cl, domain1, epoch, sigRoots[i], sig.ToETH2(), pubkey)
			if err != nil {
				return errors.Wrap(err, "verify signed data", z.Str("domain", string(domainNames[i])))
			}
		}
	}

	return nil
}

// Implement Eth2SignedData for VersionedSignedBeaconBlock.

func (VersionedSignedBeaconBlock) DomainName() signing.DomainName {
	return signing.DomainBeaconProposer
}

func (VersionedSignedBeaconBlock) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainBeaconProposer, signing.DomainBlobSidecar}
}

func (v VersionedSignedBeaconBlock) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := v.VersionedSignedBeaconBlock.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for VersionedSignedBlindedBeaconBlock.

func (VersionedSignedBlindedBeaconBlock) DomainName() signing.DomainName {
	return signing.DomainBeaconProposer
}

func (VersionedSignedBlindedBeaconBlock) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainBeaconProposer}
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

func (Attestation) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainBeaconAttester}
}

func (a Attestation) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return a.Attestation.Data.Target.Epoch, nil
}

// Implement Eth2SignedData for SignedVoluntaryExit.

func (SignedVoluntaryExit) DomainName() signing.DomainName {
	return signing.DomainExit
}

func (SignedVoluntaryExit) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainExit}
}

func (e SignedVoluntaryExit) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return e.Message.Epoch, nil
}

// Implement Eth2SignedData for VersionedSignedValidatorRegistration.

func (VersionedSignedValidatorRegistration) DomainName() signing.DomainName {
	return signing.DomainApplicationBuilder
}

func (VersionedSignedValidatorRegistration) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainApplicationBuilder}
}

func (VersionedSignedValidatorRegistration) Epoch(context.Context, eth2wrap.Client) (eth2p0.Epoch, error) {
	// Always use epoch 0 for DomainApplicationBuilder.
	return 0, nil
}

// Implement Eth2SignedData for SignedRandao.

func (SignedRandao) DomainName() signing.DomainName {
	return signing.DomainRandao
}

func (SignedRandao) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainRandao}
}

func (s SignedRandao) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return s.SignedEpoch.Epoch, nil
}

// Implement Eth2SignedData for BeaconCommitteeSelection.

func (BeaconCommitteeSelection) DomainName() signing.DomainName {
	return signing.DomainSelectionProof
}

func (BeaconCommitteeSelection) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSelectionProof}
}

func (s BeaconCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedAggregateAndProof.

func (SignedAggregateAndProof) DomainName() signing.DomainName {
	return signing.DomainAggregateAndProof
}

func (SignedAggregateAndProof) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainAggregateAndProof}
}

func (s SignedAggregateAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Aggregate.Data.Slot)
}

// Implement Eth2SignedData for SignedSyncMessage.

func (SignedSyncMessage) DomainName() signing.DomainName {
	return signing.DomainSyncCommittee
}

func (SignedSyncMessage) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSyncCommittee}
}

func (s SignedSyncMessage) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedSyncContributionAndProof.

func (SignedSyncContributionAndProof) DomainName() signing.DomainName {
	return signing.DomainContributionAndProof
}

func (SignedSyncContributionAndProof) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainContributionAndProof}
}

func (s SignedSyncContributionAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Contribution.Slot)
}

// Implement Eth2SignedData for SyncCommitteeSelection.

func (SyncCommitteeSelection) DomainName() signing.DomainName {
	return signing.DomainSyncCommitteeSelectionProof
}

func (SyncCommitteeSelection) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSyncCommitteeSelectionProof}
}

func (s SyncCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}
