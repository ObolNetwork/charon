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

package eth2wrap

// Code generated by genwrap.go. DO NOT EDIT.

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
)

// Interface assertions
var (
	_ eth2client.Service = (*Service)(nil)

	_ eth2client.AggregateAttestationProvider          = (*Service)(nil)
	_ eth2client.AggregateAttestationsSubmitter        = (*Service)(nil)
	_ eth2client.AttestationDataProvider               = (*Service)(nil)
	_ eth2client.AttestationPoolProvider               = (*Service)(nil)
	_ eth2client.AttestationsSubmitter                 = (*Service)(nil)
	_ eth2client.AttesterDutiesProvider                = (*Service)(nil)
	_ eth2client.BeaconBlockHeadersProvider            = (*Service)(nil)
	_ eth2client.BeaconBlockProposalProvider           = (*Service)(nil)
	_ eth2client.BeaconBlockRootProvider               = (*Service)(nil)
	_ eth2client.BeaconBlockSubmitter                  = (*Service)(nil)
	_ eth2client.BeaconCommitteeSubscriptionsSubmitter = (*Service)(nil)
	_ eth2client.BeaconCommitteesProvider              = (*Service)(nil)
	_ eth2client.BeaconStateProvider                   = (*Service)(nil)
	_ eth2client.BeaconStateRootProvider               = (*Service)(nil)
	_ eth2client.BlindedBeaconBlockProposalProvider    = (*Service)(nil)
	_ eth2client.BlindedBeaconBlockSubmitter           = (*Service)(nil)
	_ eth2client.DepositContractProvider               = (*Service)(nil)
	_ eth2client.DomainProvider                        = (*Service)(nil)
	_ eth2client.EventsProvider                        = (*Service)(nil)
	_ eth2client.FarFutureEpochProvider                = (*Service)(nil)
	_ eth2client.FinalityProvider                      = (*Service)(nil)
	_ eth2client.ForkProvider                          = (*Service)(nil)
	_ eth2client.ForkScheduleProvider                  = (*Service)(nil)
	_ eth2client.GenesisProvider                       = (*Service)(nil)
	_ eth2client.GenesisTimeProvider                   = (*Service)(nil)
	_ eth2client.NodeSyncingProvider                   = (*Service)(nil)
	_ eth2client.NodeVersionProvider                   = (*Service)(nil)
	_ eth2client.ProposalPreparationsSubmitter         = (*Service)(nil)
	_ eth2client.ProposerDutiesProvider                = (*Service)(nil)
	_ eth2client.SignedBeaconBlockProvider             = (*Service)(nil)
	_ eth2client.SlotDurationProvider                  = (*Service)(nil)
	_ eth2client.SlotFromStateIDProvider               = (*Service)(nil)
	_ eth2client.SlotsPerEpochProvider                 = (*Service)(nil)
	_ eth2client.SpecProvider                          = (*Service)(nil)
	_ eth2client.SyncCommitteeContributionProvider     = (*Service)(nil)
	_ eth2client.SyncCommitteeContributionsSubmitter   = (*Service)(nil)
	_ eth2client.SyncCommitteeDutiesProvider           = (*Service)(nil)
	_ eth2client.SyncCommitteeMessagesSubmitter        = (*Service)(nil)
	_ eth2client.SyncCommitteeSubscriptionsSubmitter   = (*Service)(nil)
	_ eth2client.SyncCommitteesProvider                = (*Service)(nil)
	_ eth2client.TargetAggregatorsPerCommitteeProvider = (*Service)(nil)
	_ eth2client.ValidatorBalancesProvider             = (*Service)(nil)
	_ eth2client.ValidatorsProvider                    = (*Service)(nil)
	_ eth2client.VoluntaryExitSubmitter                = (*Service)(nil)
)

type eth2Provider interface {
	eth2client.Service

	eth2client.AggregateAttestationProvider
	eth2client.AggregateAttestationsSubmitter
	eth2client.AttestationDataProvider
	eth2client.AttestationPoolProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockHeadersProvider
	eth2client.BeaconBlockProposalProvider
	eth2client.BeaconBlockRootProvider
	eth2client.BeaconBlockSubmitter
	eth2client.BeaconCommitteeSubscriptionsSubmitter
	eth2client.BeaconCommitteesProvider
	eth2client.BeaconStateProvider
	eth2client.BeaconStateRootProvider
	eth2client.BlindedBeaconBlockProposalProvider
	eth2client.BlindedBeaconBlockSubmitter
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.EventsProvider
	eth2client.FarFutureEpochProvider
	eth2client.FinalityProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeSyncingProvider
	eth2client.NodeVersionProvider
	eth2client.ProposalPreparationsSubmitter
	eth2client.ProposerDutiesProvider
	eth2client.SignedBeaconBlockProvider
	eth2client.SlotDurationProvider
	eth2client.SlotFromStateIDProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.SyncCommitteeContributionProvider
	eth2client.SyncCommitteeContributionsSubmitter
	eth2client.SyncCommitteeDutiesProvider
	eth2client.SyncCommitteeMessagesSubmitter
	eth2client.SyncCommitteeSubscriptionsSubmitter
	eth2client.SyncCommitteesProvider
	eth2client.TargetAggregatorsPerCommitteeProvider
	eth2client.ValidatorBalancesProvider
	eth2client.ValidatorsProvider
	eth2client.VoluntaryExitSubmitter
}

// SignedBeaconBlock fetches a signed beacon block given a block ID.
func (s *Service) SignedBeaconBlock(ctx context.Context, blockID string) (*spec.VersionedSignedBeaconBlock, error) {
	const label = "signed_beacon_block"
	defer latency(label)()

	res0, err := s.eth2Provider.SignedBeaconBlock(ctx, blockID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BeaconCommittees fetches all beacon committees for the epoch at the given state.
func (s *Service) BeaconCommittees(ctx context.Context, stateID string) ([]*apiv1.BeaconCommittee, error) {
	const label = "beacon_committees"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconCommittees(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BeaconCommitteesAtEpoch fetches all beacon committees for the given epoch at the given state.
func (s *Service) BeaconCommitteesAtEpoch(ctx context.Context, stateID string, epoch phase0.Epoch) ([]*apiv1.BeaconCommittee, error) {
	const label = "beacon_committees_at_epoch"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconCommitteesAtEpoch(ctx, stateID, epoch)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SyncCommittee fetches the sync committee for the given state.
func (s *Service) SyncCommittee(ctx context.Context, stateID string) (*apiv1.SyncCommittee, error) {
	const label = "sync_committee"
	defer latency(label)()

	res0, err := s.eth2Provider.SyncCommittee(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SyncCommitteeAtEpoch fetches the sync committee for the given epoch at the given state.
func (s *Service) SyncCommitteeAtEpoch(ctx context.Context, stateID string, epoch phase0.Epoch) (*apiv1.SyncCommittee, error) {
	const label = "sync_committee_at_epoch"
	defer latency(label)()

	res0, err := s.eth2Provider.SyncCommitteeAtEpoch(ctx, stateID, epoch)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// AggregateAttestation fetches the aggregate attestation given an attestation.
func (s *Service) AggregateAttestation(ctx context.Context, slot phase0.Slot, attestationDataRoot phase0.Root) (*phase0.Attestation, error) {
	const label = "aggregate_attestation"
	defer latency(label)()

	res0, err := s.eth2Provider.AggregateAttestation(ctx, slot, attestationDataRoot)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitAggregateAttestations submits aggregate attestations.
func (s *Service) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*phase0.SignedAggregateAndProof) error {
	const label = "submit_aggregate_attestations"
	defer latency(label)()

	err := s.eth2Provider.SubmitAggregateAttestations(ctx, aggregateAndProofs)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// AttestationData fetches the attestation data for the given slot and committee index.
func (s *Service) AttestationData(ctx context.Context, slot phase0.Slot, committeeIndex phase0.CommitteeIndex) (*phase0.AttestationData, error) {
	const label = "attestation_data"
	defer latency(label)()

	res0, err := s.eth2Provider.AttestationData(ctx, slot, committeeIndex)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// AttestationPool fetches the attestation pool for the given slot.
func (s *Service) AttestationPool(ctx context.Context, slot phase0.Slot) ([]*phase0.Attestation, error) {
	const label = "attestation_pool"
	defer latency(label)()

	res0, err := s.eth2Provider.AttestationPool(ctx, slot)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitAttestations submits attestations.
func (s *Service) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	const label = "submit_attestations"
	defer latency(label)()

	err := s.eth2Provider.SubmitAttestations(ctx, attestations)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// AttesterDuties obtains attester duties.
// If validatorIndicess is nil it will return all duties for the given epoch.
func (s *Service) AttesterDuties(ctx context.Context, epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) ([]*apiv1.AttesterDuty, error) {
	const label = "attester_duties"
	defer latency(label)()

	res0, err := s.eth2Provider.AttesterDuties(ctx, epoch, validatorIndices)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SyncCommitteeDuties obtains sync committee duties.
// If validatorIndicess is nil it will return all duties for the given epoch.
func (s *Service) SyncCommitteeDuties(ctx context.Context, epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) ([]*apiv1.SyncCommitteeDuty, error) {
	const label = "sync_committee_duties"
	defer latency(label)()

	res0, err := s.eth2Provider.SyncCommitteeDuties(ctx, epoch, validatorIndices)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (s *Service) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	const label = "submit_sync_committee_messages"
	defer latency(label)()

	err := s.eth2Provider.SubmitSyncCommitteeMessages(ctx, messages)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// SubmitSyncCommitteeSubscriptions subscribes to sync committees.
func (s *Service) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error {
	const label = "submit_sync_committee_subscriptions"
	defer latency(label)()

	err := s.eth2Provider.SubmitSyncCommitteeSubscriptions(ctx, subscriptions)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// SyncCommitteeContribution provides a sync committee contribution.
func (s *Service) SyncCommitteeContribution(ctx context.Context, slot phase0.Slot, subcommitteeIndex uint64, beaconBlockRoot phase0.Root) (*altair.SyncCommitteeContribution, error) {
	const label = "sync_committee_contribution"
	defer latency(label)()

	res0, err := s.eth2Provider.SyncCommitteeContribution(ctx, slot, subcommitteeIndex, beaconBlockRoot)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (s *Service) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	const label = "submit_sync_committee_contributions"
	defer latency(label)()

	err := s.eth2Provider.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// BeaconBlockHeader provides the block header of a given block ID.
func (s *Service) BeaconBlockHeader(ctx context.Context, blockID string) (*apiv1.BeaconBlockHeader, error) {
	const label = "beacon_block_header"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconBlockHeader(ctx, blockID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BeaconBlockProposal fetches a proposed beacon block for signing.
func (s *Service) BeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	const label = "beacon_block_proposal"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BeaconBlockRoot fetches a block's root given a block ID.
func (s *Service) BeaconBlockRoot(ctx context.Context, blockID string) (*phase0.Root, error) {
	const label = "beacon_block_root"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconBlockRoot(ctx, blockID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitBeaconBlock submits a beacon block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	const label = "submit_beacon_block"
	defer latency(label)()

	err := s.eth2Provider.SubmitBeaconBlock(ctx, block)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// SubmitBeaconCommitteeSubscriptions subscribes to beacon committees.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error {
	const label = "submit_beacon_committee_subscriptions"
	defer latency(label)()

	err := s.eth2Provider.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// BeaconState fetches a beacon state given a state ID.
func (s *Service) BeaconState(ctx context.Context, stateID string) (*spec.VersionedBeaconState, error) {
	const label = "beacon_state"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconState(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BeaconStateRoot fetches a beacon state root given a state ID.
func (s *Service) BeaconStateRoot(ctx context.Context, stateID string) (*phase0.Root, error) {
	const label = "beacon_state_root"
	defer latency(label)()

	res0, err := s.eth2Provider.BeaconStateRoot(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// BlindedBeaconBlockProposal fetches a blinded proposed beacon block for signing.
func (s *Service) BlindedBeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	const label = "blinded_beacon_block_proposal"
	defer latency(label)()

	res0, err := s.eth2Provider.BlindedBeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitBlindedBeaconBlock submits a beacon block.
func (s *Service) SubmitBlindedBeaconBlock(ctx context.Context, block *api.VersionedSignedBlindedBeaconBlock) error {
	const label = "submit_blinded_beacon_block"
	defer latency(label)()

	err := s.eth2Provider.SubmitBlindedBeaconBlock(ctx, block)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// Events feeds requested events with the given topics to the supplied handler.
func (s *Service) Events(ctx context.Context, topics []string, handler eth2client.EventHandlerFunc) error {
	const label = "events"
	defer latency(label)()

	err := s.eth2Provider.Events(ctx, topics, handler)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// Finality provides the finality given a state ID.
func (s *Service) Finality(ctx context.Context, stateID string) (*apiv1.Finality, error) {
	const label = "finality"
	defer latency(label)()

	res0, err := s.eth2Provider.Finality(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// Fork fetches fork information for the given state.
func (s *Service) Fork(ctx context.Context, stateID string) (*phase0.Fork, error) {
	const label = "fork"
	defer latency(label)()

	res0, err := s.eth2Provider.Fork(ctx, stateID)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// NodeSyncing provides the state of the node's synchronization with the chain.
func (s *Service) NodeSyncing(ctx context.Context) (*apiv1.SyncState, error) {
	const label = "node_syncing"
	defer latency(label)()

	res0, err := s.eth2Provider.NodeSyncing(ctx)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitProposalPreparations provides the beacon node with information required if a proposal for the given validators
// shows up in the next epoch.
func (s *Service) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error {
	const label = "submit_proposal_preparations"
	defer latency(label)()

	err := s.eth2Provider.SubmitProposalPreparations(ctx, preparations)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}

// ProposerDuties obtains proposer duties for the given epoch.
// If validatorIndices is empty all duties are returned, otherwise only matching duties are returned.
func (s *Service) ProposerDuties(ctx context.Context, epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) ([]*apiv1.ProposerDuty, error) {
	const label = "proposer_duties"
	defer latency(label)()

	res0, err := s.eth2Provider.ProposerDuties(ctx, epoch, validatorIndices)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// ValidatorBalances provides the validator balances for a given state.
// stateID can be a slot number or state root, or one of the special values "genesis", "head", "justified" or "finalized".
// validatorIndices is a list of validator indices to restrict the returned values.  If no validators are supplied no filter
// will be applied.
func (s *Service) ValidatorBalances(ctx context.Context, stateID string, validatorIndices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]phase0.Gwei, error) {
	const label = "validator_balances"
	defer latency(label)()

	res0, err := s.eth2Provider.ValidatorBalances(ctx, stateID, validatorIndices)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// Validators provides the validators, with their balance and status, for a given state.
// stateID can be a slot number or state root, or one of the special values "genesis", "head", "justified" or "finalized".
// validatorIndices is a list of validator indices to restrict the returned values.  If no validators IDs are supplied no filter
// will be applied.
func (s *Service) Validators(ctx context.Context, stateID string, validatorIndices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	const label = "validators"
	defer latency(label)()

	res0, err := s.eth2Provider.Validators(ctx, stateID, validatorIndices)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// ValidatorsByPubKey provides the validators, with their balance and status, for a given state.
// stateID can be a slot number or state root, or one of the special values "genesis", "head", "justified" or "finalized".
// validatorPubKeys is a list of validator public keys to restrict the returned values.  If no validators public keys are
// supplied no filter will be applied.
func (s *Service) ValidatorsByPubKey(ctx context.Context, stateID string, validatorPubKeys []phase0.BLSPubKey) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	const label = "validators_by_pub_key"
	defer latency(label)()

	res0, err := s.eth2Provider.ValidatorsByPubKey(ctx, stateID, validatorPubKeys)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return res0, err
}

// SubmitVoluntaryExit submits a voluntary exit.
func (s *Service) SubmitVoluntaryExit(ctx context.Context, voluntaryExit *phase0.SignedVoluntaryExit) error {
	const label = "submit_voluntary_exit"
	defer latency(label)()

	err := s.eth2Provider.SubmitVoluntaryExit(ctx, voluntaryExit)
	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2http")
	}

	return err
}
