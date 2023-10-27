// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"

	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

var (
	_ Eth2SignedData = VersionedSignedProposal{}
	_ Eth2SignedData = Attestation{}
	_ Eth2SignedData = SignedVoluntaryExit{}
	_ Eth2SignedData = VersionedSignedBlindedProposal{}
	_ Eth2SignedData = VersionedSignedValidatorRegistration{}
	_ Eth2SignedData = SignedRandao{}
	_ Eth2SignedData = BeaconCommitteeSelection{}
	_ Eth2SignedData = SignedAggregateAndProof{}
	_ Eth2SignedData = SignedSyncMessage{}
	_ Eth2SignedData = SignedSyncContributionAndProof{}
	_ Eth2SignedData = SyncCommitteeSelection{}
)

// VerifyEth2SignedData verifies signatures associated with the given Eth2SignedData.
func VerifyEth2SignedData(ctx context.Context, eth2Cl eth2wrap.Client, data Eth2SignedData, pubkey tbls.PublicKey) error {
	epoch, err := data.Epoch(ctx, eth2Cl)
	if err != nil {
		return err
	}

	sigs := data.Signatures()
	domainNames := data.DomainNames()
	msgRoots, err := data.MessageRoots()
	if err != nil {
		return err
	}

	if len(domainNames) != len(msgRoots) {
		return errors.New("mismatching lengths", z.Int("domain_names", len(domainNames)), z.Int("message_roots", len(msgRoots)))
	}
	if len(domainNames) != len(sigs) {
		return errors.New("mismatching lengths", z.Int("domain_names", len(domainNames)), z.Int("signatures", len(sigs)))
	}

	for i, sig := range sigs {
		err = signing.Verify(ctx, eth2Cl, domainNames[i], epoch, msgRoots[i], sig.ToETH2(), pubkey)
		if err != nil {
			return errors.Wrap(err, "verify signed data", z.Str("domain", string(domainNames[i])))
		}
	}

	return nil
}

// Implement Eth2SignedData for VersionedSignedProposal.

func (p VersionedSignedProposal) DomainNames() []signing.DomainName {
	switch p.Version {
	case eth2spec.DataVersionPhase0:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionAltair:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionBellatrix:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionCapella:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionDeneb:
		var domains []signing.DomainName
		domains = append(domains, signing.DomainBeaconProposer) // Deneb beacon block
		for range p.Deneb.SignedBlobSidecars {
			domains = append(domains, signing.DomainBlobSidecar) // Deneb blob sidecar
		}

		return domains
	default:
		return []signing.DomainName{signing.DomainBeaconProposer}
	}
}

func (p VersionedSignedProposal) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := p.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for VersionedSignedBlindedProposal.

func (p VersionedSignedBlindedProposal) DomainNames() []signing.DomainName {
	switch p.Version {
	case eth2spec.DataVersionBellatrix:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionCapella:
		return []signing.DomainName{signing.DomainBeaconProposer}
	case eth2spec.DataVersionDeneb:
		var domains []signing.DomainName
		domains = append(domains, signing.DomainBeaconProposer) // Deneb beacon block
		for range p.Deneb.SignedBlindedBlobSidecars {
			domains = append(domains, signing.DomainBlobSidecar) // Deneb blob sidecar
		}

		return domains
	default:
		return []signing.DomainName{signing.DomainBeaconProposer}
	}
}

func (p VersionedSignedBlindedProposal) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	slot, err := p.VersionedSignedBlindedProposal.Slot()
	if err != nil {
		return 0, err
	}

	return eth2util.EpochFromSlot(ctx, eth2Cl, slot)
}

// Implement Eth2SignedData for Attestation.

func (Attestation) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainBeaconAttester}
}

func (a Attestation) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return a.Attestation.Data.Target.Epoch, nil
}

// Implement Eth2SignedData for SignedVoluntaryExit.

func (SignedVoluntaryExit) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainExit}
}

func (e SignedVoluntaryExit) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return e.Message.Epoch, nil
}

// Implement Eth2SignedData for VersionedSignedValidatorRegistration.

func (VersionedSignedValidatorRegistration) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainApplicationBuilder}
}

func (VersionedSignedValidatorRegistration) Epoch(context.Context, eth2wrap.Client) (eth2p0.Epoch, error) {
	// Always use epoch 0 for DomainApplicationBuilder.
	return 0, nil
}

// Implement Eth2SignedData for SignedRandao.

func (SignedRandao) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainRandao}
}

func (s SignedRandao) Epoch(_ context.Context, _ eth2wrap.Client) (eth2p0.Epoch, error) {
	return s.SignedEpoch.Epoch, nil
}

// Implement Eth2SignedData for BeaconCommitteeSelection.

func (BeaconCommitteeSelection) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSelectionProof}
}

func (s BeaconCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedAggregateAndProof.

func (SignedAggregateAndProof) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainAggregateAndProof}
}

func (s SignedAggregateAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Aggregate.Data.Slot)
}

// Implement Eth2SignedData for SignedSyncMessage.

func (SignedSyncMessage) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSyncCommittee}
}

func (s SignedSyncMessage) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}

// Implement Eth2SignedData for SignedSyncContributionAndProof.

func (SignedSyncContributionAndProof) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainContributionAndProof}
}

func (s SignedSyncContributionAndProof) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Message.Contribution.Slot)
}

// Implement Eth2SignedData for SyncCommitteeSelection.

func (SyncCommitteeSelection) DomainNames() []signing.DomainName {
	return []signing.DomainName{signing.DomainSyncCommitteeSelectionProof}
}

func (s SyncCommitteeSelection) Epoch(ctx context.Context, eth2Cl eth2wrap.Client) (eth2p0.Epoch, error) {
	return eth2util.EpochFromSlot(ctx, eth2Cl, s.Slot)
}
