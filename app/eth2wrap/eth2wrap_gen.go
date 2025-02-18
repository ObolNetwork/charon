// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

// Code generated by genwrap.go. DO NOT EDIT.

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// Client defines all go-eth2-client interfaces used in charon.
type Client interface {
	eth2client.Service
	eth2exp.BeaconCommitteeSelectionAggregator
	eth2exp.SyncCommitteeSelectionAggregator
	eth2exp.ProposerConfigProvider
	BlockAttestationsProvider
	BeaconStateCommitteesProvider
	NodePeerCountProvider

	CachedValidatorsProvider
	SetValidatorCache(func(context.Context) (ActiveValidators, CompleteValidators, error))

	SetForkVersion(forkVersion [4]byte)

	eth2client.AggregateAttestationProvider
	eth2client.AggregateAttestationsSubmitter
	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockRootProvider
	eth2client.BeaconCommitteeSubscriptionsSubmitter
	eth2client.BlindedProposalSubmitter
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeSyncingProvider
	eth2client.NodeVersionProvider
	eth2client.ProposalPreparationsSubmitter
	eth2client.ProposalProvider
	eth2client.ProposalSubmitter
	eth2client.ProposerDutiesProvider
	eth2client.SignedBeaconBlockProvider
	eth2client.SlotDurationProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.SyncCommitteeContributionProvider
	eth2client.SyncCommitteeContributionsSubmitter
	eth2client.SyncCommitteeDutiesProvider
	eth2client.SyncCommitteeMessagesSubmitter
	eth2client.SyncCommitteeSubscriptionsSubmitter
	eth2client.ValidatorRegistrationsSubmitter
	eth2client.ValidatorsProvider
	eth2client.VoluntaryExitSubmitter
}

// SlotDuration provides the duration of a slot of the chain.
//
// Deprecated: use Spec()
// Note this endpoint is cached in go-eth2-client.
func (m multi) SlotDuration(ctx context.Context) (time.Duration, error) {
	const label = "slot_duration"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (time.Duration, error) {
			return args.client.SlotDuration(ctx)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SlotsPerEpoch provides the slots per epoch of the chain.
//
// Deprecated: use Spec()
// Note this endpoint is cached in go-eth2-client.
func (m multi) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	const label = "slots_per_epoch"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (uint64, error) {
			return args.client.SlotsPerEpoch(ctx)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SignedBeaconBlock fetches a signed beacon block given a block ID.
func (m multi) SignedBeaconBlock(ctx context.Context, opts *api.SignedBeaconBlockOpts) (*api.Response[*spec.VersionedSignedBeaconBlock], error) {
	const label = "signed_beacon_block"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*spec.VersionedSignedBeaconBlock], error) {
			return args.client.SignedBeaconBlock(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// AggregateAttestation fetches the aggregate attestation for the given options to v1 beacon node endpoint.
func (m multi) AggregateAttestation(ctx context.Context, opts *api.AggregateAttestationOpts) (*api.Response[*phase0.Attestation], error) {
	const label = "aggregate_attestation"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*phase0.Attestation], error) {
			return args.client.AggregateAttestation(ctx, opts)
		},
		isAggregateAttestationOk, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// AggregateAttestationV2 fetches the aggregate attestation for the given options to v2 beacon node endpoint.
func (m multi) AggregateAttestationV2(ctx context.Context, opts *api.AggregateAttestationOpts) (*api.Response[*spec.VersionedAttestation], error) {
	const label = "aggregate_attestation_v2"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*spec.VersionedAttestation], error) {
			return args.client.AggregateAttestationV2(ctx, opts)
		},
		isAggregateAttestationOkV2, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitAggregateAttestations submits aggregate attestations to v1 beacon node endpoint.
func (m multi) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*phase0.SignedAggregateAndProof) error {
	const label = "submit_aggregate_attestations"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitAggregateAttestations(ctx, aggregateAndProofs)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitAggregateAttestationsV2 submits aggregate attestations to v2 beacon node endpoint..
func (m multi) SubmitAggregateAttestationsV2(ctx context.Context, opts *api.SubmitAggregateAttestationsOpts) error {
	const label = "submit_aggregate_attestations_v2"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitAggregateAttestationsV2(ctx, opts)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// AttestationData fetches the attestation data for the given options.
func (m multi) AttestationData(ctx context.Context, opts *api.AttestationDataOpts) (*api.Response[*phase0.AttestationData], error) {
	const label = "attestation_data"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*phase0.AttestationData], error) {
			return args.client.AttestationData(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitAttestations submits attestations on v1 BN endpoint.
func (m multi) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	const label = "submit_attestations"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitAttestations(ctx, attestations)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitAttestationsV2 submits attestations on v2 BN endpoint.
func (m multi) SubmitAttestationsV2(ctx context.Context, opts *api.SubmitAttestationsOpts) error {
	const label = "submit_attestations_v2"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitAttestationsV2(ctx, opts)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// AttesterDuties obtains attester duties.
func (m multi) AttesterDuties(ctx context.Context, opts *api.AttesterDutiesOpts) (*api.Response[[]*apiv1.AttesterDuty], error) {
	const label = "attester_duties"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[[]*apiv1.AttesterDuty], error) {
			return args.client.AttesterDuties(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// DepositContract provides details of the execution deposit contract for the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) DepositContract(ctx context.Context, opts *api.DepositContractOpts) (*api.Response[*apiv1.DepositContract], error) {
	const label = "deposit_contract"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*apiv1.DepositContract], error) {
			return args.client.DepositContract(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SyncCommitteeDuties obtains sync committee duties.
// If validatorIndices is nil it will return all duties for the given epoch.
func (m multi) SyncCommitteeDuties(ctx context.Context, opts *api.SyncCommitteeDutiesOpts) (*api.Response[[]*apiv1.SyncCommitteeDuty], error) {
	const label = "sync_committee_duties"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[[]*apiv1.SyncCommitteeDuty], error) {
			return args.client.SyncCommitteeDuties(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (m multi) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	const label = "submit_sync_committee_messages"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitSyncCommitteeMessages(ctx, messages)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitSyncCommitteeSubscriptions subscribes to sync committees.
func (m multi) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error {
	const label = "submit_sync_committee_subscriptions"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitSyncCommitteeSubscriptions(ctx, subscriptions)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SyncCommitteeContribution provides a sync committee contribution.
func (m multi) SyncCommitteeContribution(ctx context.Context, opts *api.SyncCommitteeContributionOpts) (*api.Response[*altair.SyncCommitteeContribution], error) {
	const label = "sync_committee_contribution"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*altair.SyncCommitteeContribution], error) {
			return args.client.SyncCommitteeContribution(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (m multi) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	const label = "submit_sync_committee_contributions"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// Proposal fetches a proposal for signing.
func (m multi) Proposal(ctx context.Context, opts *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	const label = "proposal"
	defer latency(ctx, label, true)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*api.VersionedProposal], error) {
			return args.client.Proposal(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// BeaconBlockRoot fetches a block's root given a set of options.
// Note this endpoint is cached in go-eth2-client.
func (m multi) BeaconBlockRoot(ctx context.Context, opts *api.BeaconBlockRootOpts) (*api.Response[*phase0.Root], error) {
	const label = "beacon_block_root"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*phase0.Root], error) {
			return args.client.BeaconBlockRoot(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitProposal submits a proposal.
func (m multi) SubmitProposal(ctx context.Context, opts *api.SubmitProposalOpts) error {
	const label = "submit_proposal"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitProposal(ctx, opts)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitBeaconCommitteeSubscriptions subscribes to beacon committees.
func (m multi) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error {
	const label = "submit_beacon_committee_subscriptions"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitBlindedProposal submits a beacon block.
func (m multi) SubmitBlindedProposal(ctx context.Context, opts *api.SubmitBlindedProposalOpts) error {
	const label = "submit_blinded_proposal"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitBlindedProposal(ctx, opts)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// SubmitValidatorRegistrations submits a validator registration.
func (m multi) SubmitValidatorRegistrations(ctx context.Context, registrations []*api.VersionedSignedValidatorRegistration) error {
	const label = "submit_validator_registrations"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitValidatorRegistrations(ctx, registrations)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// Fork fetches fork information for the given state.
func (m multi) Fork(ctx context.Context, opts *api.ForkOpts) (*api.Response[*phase0.Fork], error) {
	const label = "fork"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*phase0.Fork], error) {
			return args.client.Fork(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// ForkSchedule provides details of past and future changes in the chain's fork version.
func (m multi) ForkSchedule(ctx context.Context, opts *api.ForkScheduleOpts) (*api.Response[[]*phase0.Fork], error) {
	const label = "fork_schedule"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[[]*phase0.Fork], error) {
			return args.client.ForkSchedule(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// Genesis fetches genesis information for the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Genesis(ctx context.Context, opts *api.GenesisOpts) (*api.Response[*apiv1.Genesis], error) {
	const label = "genesis"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*apiv1.Genesis], error) {
			return args.client.Genesis(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// NodeSyncing provides the state of the node's synchronization with the chain.
func (m multi) NodeSyncing(ctx context.Context, opts *api.NodeSyncingOpts) (*api.Response[*apiv1.SyncState], error) {
	const label = "node_syncing"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[*apiv1.SyncState], error) {
			return args.client.NodeSyncing(ctx, opts)
		},
		isSyncStateOk, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// NodeVersion returns a free-text string with the node version.
// Note this endpoint is cached in go-eth2-client.
func (m multi) NodeVersion(ctx context.Context, opts *api.NodeVersionOpts) (*api.Response[string], error) {
	const label = "node_version"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[string], error) {
			return args.client.NodeVersion(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitProposalPreparations provides the beacon node with information required if a proposal for the given validators
// shows up in the next epoch.
func (m multi) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error {
	const label = "submit_proposal_preparations"
	defer latency(ctx, label, true)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitProposalPreparations(ctx, preparations)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// ProposerDuties obtains proposer duties for the given options.
func (m multi) ProposerDuties(ctx context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	const label = "proposer_duties"
	defer latency(ctx, label, false)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[[]*apiv1.ProposerDuty], error) {
			return args.client.ProposerDuties(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// Spec provides the spec information of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Spec(ctx context.Context, opts *api.SpecOpts) (*api.Response[map[string]any], error) {
	const label = "spec"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[map[string]any], error) {
			return args.client.Spec(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// Validators provides the validators, with their balance and status, for the given options.
func (m multi) Validators(ctx context.Context, opts *api.ValidatorsOpts) (*api.Response[map[phase0.ValidatorIndex]*apiv1.Validator], error) {
	const label = "validators"
	defer latency(ctx, label, true)()

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*api.Response[map[phase0.ValidatorIndex]*apiv1.Validator], error) {
			return args.client.Validators(ctx, opts)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitVoluntaryExit submits a voluntary exit.
func (m multi) SubmitVoluntaryExit(ctx context.Context, voluntaryExit *phase0.SignedVoluntaryExit) error {
	const label = "submit_voluntary_exit"
	defer latency(ctx, label, false)()

	err := submit(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) error {
			return args.client.SubmitVoluntaryExit(ctx, voluntaryExit)
		},
		m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return err
}

// Domain provides a domain for a given domain type at a given epoch.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Domain(ctx context.Context, domainType phase0.DomainType, epoch phase0.Epoch) (phase0.Domain, error) {
	const label = "domain"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (phase0.Domain, error) {
			return args.client.Domain(ctx, domainType, epoch)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// GenesisDomain returns the domain for the given domain type at genesis.
// N.B. this is not always the same as the domain at epoch 0.  It is possible
// for a chain's fork schedule to have multiple forks at genesis.  In this situation,
// GenesisDomain() will return the first, and Domain() will return the last.
// Note this endpoint is cached in go-eth2-client.
func (m multi) GenesisDomain(ctx context.Context, domainType phase0.DomainType) (phase0.Domain, error) {
	const label = "genesis_domain"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (phase0.Domain, error) {
			return args.client.GenesisDomain(ctx, domainType)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// GenesisTime provides the genesis time of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) GenesisTime(ctx context.Context) (time.Time, error) {
	const label = "genesis_time"

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (time.Time, error) {
			return args.client.GenesisTime(ctx)
		},
		nil, m.selector,
	)

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SlotDuration provides the duration of a slot of the chain.
//
// Deprecated: use Spec()
func (l *lazy) SlotDuration(ctx context.Context) (res0 time.Duration, err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.SlotDuration(ctx)
}

// SlotsPerEpoch provides the slots per epoch of the chain.
//
// Deprecated: use Spec()
func (l *lazy) SlotsPerEpoch(ctx context.Context) (res0 uint64, err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.SlotsPerEpoch(ctx)
}

// SignedBeaconBlock fetches a signed beacon block given a block ID.
func (l *lazy) SignedBeaconBlock(ctx context.Context, opts *api.SignedBeaconBlockOpts) (res0 *api.Response[*spec.VersionedSignedBeaconBlock], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.SignedBeaconBlock(ctx, opts)
}

// AggregateAttestation fetches the aggregate attestation for the given options to v1 beacon node endpoint.
func (l *lazy) AggregateAttestation(ctx context.Context, opts *api.AggregateAttestationOpts) (res0 *api.Response[*phase0.Attestation], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.AggregateAttestation(ctx, opts)
}

// AggregateAttestationV2 fetches the aggregate attestation for the given options to v2 beacon node endpoint.
func (l *lazy) AggregateAttestationV2(ctx context.Context, opts *api.AggregateAttestationOpts) (res0 *api.Response[*spec.VersionedAttestation], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.AggregateAttestationV2(ctx, opts)
}

// SubmitAggregateAttestations submits aggregate attestations to v1 beacon node endpoint.
func (l *lazy) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*phase0.SignedAggregateAndProof) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitAggregateAttestations(ctx, aggregateAndProofs)
}

// SubmitAggregateAttestationsV2 submits aggregate attestations to v2 beacon node endpoint..
func (l *lazy) SubmitAggregateAttestationsV2(ctx context.Context, opts *api.SubmitAggregateAttestationsOpts) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitAggregateAttestationsV2(ctx, opts)
}

// AttestationData fetches the attestation data for the given options.
func (l *lazy) AttestationData(ctx context.Context, opts *api.AttestationDataOpts) (res0 *api.Response[*phase0.AttestationData], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.AttestationData(ctx, opts)
}

// SubmitAttestations submits attestations on v1 BN endpoint.
func (l *lazy) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitAttestations(ctx, attestations)
}

// SubmitAttestationsV2 submits attestations on v2 BN endpoint.
func (l *lazy) SubmitAttestationsV2(ctx context.Context, opts *api.SubmitAttestationsOpts) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitAttestationsV2(ctx, opts)
}

// AttesterDuties obtains attester duties.
func (l *lazy) AttesterDuties(ctx context.Context, opts *api.AttesterDutiesOpts) (res0 *api.Response[[]*apiv1.AttesterDuty], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.AttesterDuties(ctx, opts)
}

// DepositContract provides details of the execution deposit contract for the chain.
func (l *lazy) DepositContract(ctx context.Context, opts *api.DepositContractOpts) (res0 *api.Response[*apiv1.DepositContract], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.DepositContract(ctx, opts)
}

// SyncCommitteeDuties obtains sync committee duties.
// If validatorIndices is nil it will return all duties for the given epoch.
func (l *lazy) SyncCommitteeDuties(ctx context.Context, opts *api.SyncCommitteeDutiesOpts) (res0 *api.Response[[]*apiv1.SyncCommitteeDuty], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.SyncCommitteeDuties(ctx, opts)
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (l *lazy) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitSyncCommitteeMessages(ctx, messages)
}

// SubmitSyncCommitteeSubscriptions subscribes to sync committees.
func (l *lazy) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitSyncCommitteeSubscriptions(ctx, subscriptions)
}

// SyncCommitteeContribution provides a sync committee contribution.
func (l *lazy) SyncCommitteeContribution(ctx context.Context, opts *api.SyncCommitteeContributionOpts) (res0 *api.Response[*altair.SyncCommitteeContribution], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.SyncCommitteeContribution(ctx, opts)
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (l *lazy) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
}

// Proposal fetches a proposal for signing.
func (l *lazy) Proposal(ctx context.Context, opts *api.ProposalOpts) (res0 *api.Response[*api.VersionedProposal], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Proposal(ctx, opts)
}

// BeaconBlockRoot fetches a block's root given a set of options.
func (l *lazy) BeaconBlockRoot(ctx context.Context, opts *api.BeaconBlockRootOpts) (res0 *api.Response[*phase0.Root], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.BeaconBlockRoot(ctx, opts)
}

// SubmitProposal submits a proposal.
func (l *lazy) SubmitProposal(ctx context.Context, opts *api.SubmitProposalOpts) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitProposal(ctx, opts)
}

// SubmitBeaconCommitteeSubscriptions subscribes to beacon committees.
func (l *lazy) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions)
}

// SubmitBlindedProposal submits a beacon block.
func (l *lazy) SubmitBlindedProposal(ctx context.Context, opts *api.SubmitBlindedProposalOpts) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitBlindedProposal(ctx, opts)
}

// SubmitValidatorRegistrations submits a validator registration.
func (l *lazy) SubmitValidatorRegistrations(ctx context.Context, registrations []*api.VersionedSignedValidatorRegistration) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitValidatorRegistrations(ctx, registrations)
}

// Fork fetches fork information for the given state.
func (l *lazy) Fork(ctx context.Context, opts *api.ForkOpts) (res0 *api.Response[*phase0.Fork], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Fork(ctx, opts)
}

// ForkSchedule provides details of past and future changes in the chain's fork version.
func (l *lazy) ForkSchedule(ctx context.Context, opts *api.ForkScheduleOpts) (res0 *api.Response[[]*phase0.Fork], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.ForkSchedule(ctx, opts)
}

// Genesis fetches genesis information for the chain.
func (l *lazy) Genesis(ctx context.Context, opts *api.GenesisOpts) (res0 *api.Response[*apiv1.Genesis], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Genesis(ctx, opts)
}

// NodeSyncing provides the state of the node's synchronization with the chain.
func (l *lazy) NodeSyncing(ctx context.Context, opts *api.NodeSyncingOpts) (res0 *api.Response[*apiv1.SyncState], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.NodeSyncing(ctx, opts)
}

// NodeVersion returns a free-text string with the node version.
func (l *lazy) NodeVersion(ctx context.Context, opts *api.NodeVersionOpts) (res0 *api.Response[string], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.NodeVersion(ctx, opts)
}

// SubmitProposalPreparations provides the beacon node with information required if a proposal for the given validators
// shows up in the next epoch.
func (l *lazy) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitProposalPreparations(ctx, preparations)
}

// ProposerDuties obtains proposer duties for the given options.
func (l *lazy) ProposerDuties(ctx context.Context, opts *api.ProposerDutiesOpts) (res0 *api.Response[[]*apiv1.ProposerDuty], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.ProposerDuties(ctx, opts)
}

// Spec provides the spec information of the chain.
func (l *lazy) Spec(ctx context.Context, opts *api.SpecOpts) (res0 *api.Response[map[string]any], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Spec(ctx, opts)
}

// Validators provides the validators, with their balance and status, for the given options.
func (l *lazy) Validators(ctx context.Context, opts *api.ValidatorsOpts) (res0 *api.Response[map[phase0.ValidatorIndex]*apiv1.Validator], err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Validators(ctx, opts)
}

// SubmitVoluntaryExit submits a voluntary exit.
func (l *lazy) SubmitVoluntaryExit(ctx context.Context, voluntaryExit *phase0.SignedVoluntaryExit) (err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return err
	}

	return cl.SubmitVoluntaryExit(ctx, voluntaryExit)
}

// Domain provides a domain for a given domain type at a given epoch.
func (l *lazy) Domain(ctx context.Context, domainType phase0.DomainType, epoch phase0.Epoch) (res0 phase0.Domain, err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.Domain(ctx, domainType, epoch)
}

// GenesisDomain returns the domain for the given domain type at genesis.
// N.B. this is not always the same as the domain at epoch 0.  It is possible
// for a chain's fork schedule to have multiple forks at genesis.  In this situation,
// GenesisDomain() will return the first, and Domain() will return the last.
func (l *lazy) GenesisDomain(ctx context.Context, domainType phase0.DomainType) (res0 phase0.Domain, err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.GenesisDomain(ctx, domainType)
}

// GenesisTime provides the genesis time of the chain.
func (l *lazy) GenesisTime(ctx context.Context) (res0 time.Time, err error) {
	cl, err := l.getOrCreateClient(ctx)
	if err != nil {
		return res0, err
	}

	return cl.GenesisTime(ctx)
}
