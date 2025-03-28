// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package beaconmock provides a mock beacon node server and client primarily for testing.
//
//	 beaconmock.Mock     validatorapi.Router
//	┌────┬──────────┐      ┌───────────┐
//	│    │HTTPServer◄──────┤ proxy     │
//	│    └────▲─────┐ http │           │           VC
//	│         │     │      │           ◄────────── (validatormock)
//	│         │http │      │ served    │   http    (lighthouse)
//	│      ┌──┴─────┤      │ endpoints │           (teku)
//	│      │HTTPMock│      └────┬──────┘
//	└──────┴────────┘           │go
//	       ▲                    │
//	       │  ┌─────────────────▼──────┐
//	       │go│                        │
//	       └──┤core workflow components│
//	          │                        │
//	          └────────────────────────┘
//
//	HTTPServer: Serves stubs and static.json endpoints. Used by Mock and proxy.
//	HTTPMock: *eth2http.Service client connected to HTTPServer.
//	Mock: Wraps HTTPMock, adds customisable logic. Used by simnet core workflow components.
package beaconmock

import (
	"context"
	"net/http"
	"strconv"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/statecomm"
)

// Interface assertions.
var (
	_ HTTPMock        = Mock{}
	_ eth2wrap.Client = Mock{}
)

// New returns a new beacon client mock configured with the default and provided options.
func New(opts ...Option) (Mock, error) {
	// Configure http mock first.
	temp := defaultHTTPMock()
	for _, opt := range opts {
		opt(&temp)
	}

	headProducer := newHeadProducer()

	httpMock, httpServer, err := newHTTPMock(headProducer.Handlers(), temp.overrides...)
	if err != nil {
		return Mock{}, err
	}

	// Then configure the mock
	mock := defaultMock(httpMock, httpServer, temp.clock, headProducer)
	for _, opt := range opts {
		opt(&mock)
	}

	if err := headProducer.Start(httpMock); err != nil {
		return Mock{}, err
	}

	return mock, nil
}

// defaultHTTPMock returns a mock with default http mock overrides.
func defaultHTTPMock() Mock {
	// Default to recent genesis for lower slot and epoch numbers.
	genesis := time.Date(2022, 3, 1, 0, 0, 0, 0, time.UTC)
	return Mock{
		clock: clockwork.NewRealClock(),
		overrides: []staticOverride{
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "CONFIG_NAME",
				Value:    "charon-simnet",
			},
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "SLOTS_PER_EPOCH",
				Value:    "16",
			},
			{
				Endpoint: "/eth/v1/config/spec",
				Key:      "SECONDS_PER_SLOT",
				Value:    "12",
			},
			{
				Endpoint: "/eth/v1/beacon/genesis",
				Key:      "genesis_time",
				Value:    strconv.FormatInt(genesis.Unix(), 10),
			},
		},
		IsActiveFunc: func() bool { return true },
		IsSyncedFunc: func() bool { return true },
	}
}

// WithForkVersion sets the fork version provided in the Mock instance.
func WithForkVersion(forkVersion [4]byte) Option {
	return func(mock *Mock) {
		mock.forkVersion = forkVersion
	}
}

// Mock provides a mock beacon client and implements eth2wrap.Client.
// Create a new instance with default behaviour via New and then override any function.
type Mock struct {
	HTTPMock

	httpServer   *http.Server
	overrides    []staticOverride
	clock        clockwork.Clock
	headProducer *headProducer
	forkVersion  [4]byte

	IsActiveFunc                           func() bool
	IsSyncedFunc                           func() bool
	CachedValidatorsFunc                   func(ctx context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error)
	AttestationDataFunc                    func(context.Context, eth2p0.Slot, eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc                     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	BlockAttestationsFunc                  func(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error)
	BlockAttestationsV2Func                func(ctx context.Context, stateID string) ([]*eth2spec.VersionedAttestation, error)
	BeaconStateCommitteesFunc              func(ctx context.Context, slot uint64) ([]*statecomm.StateCommittee, error)
	NodePeerCountFunc                      func(ctx context.Context) (int, error)
	ProposalFunc                           func(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error)
	SignedBeaconBlockFunc                  func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error)
	ProposerDutiesFunc                     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	SubmitAttestationsFunc                 func(context.Context, []*eth2p0.Attestation) error
	SubmitAttestationsV2Func               func(context.Context, *eth2api.SubmitAttestationsOpts) error
	SubmitProposalFunc                     func(context.Context, *eth2api.SubmitProposalOpts) error
	SubmitBlindedProposalFunc              func(context.Context, *eth2api.SubmitBlindedProposalOpts) error
	SubmitVoluntaryExitFunc                func(context.Context, *eth2p0.SignedVoluntaryExit) error
	ValidatorsByPubKeyFunc                 func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsFunc                         func(context.Context, *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	GenesisFunc                            func(context.Context, *eth2api.GenesisOpts) (*eth2v1.Genesis, error)
	NodeSyncingFunc                        func(context.Context, *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error)
	SubmitValidatorRegistrationsFunc       func(context.Context, []*eth2api.VersionedSignedValidatorRegistration) error
	SlotsPerEpochFunc                      func(context.Context) (uint64, error)
	AggregateBeaconCommitteeSelectionsFunc func(context.Context, []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error)
	AggregateSyncCommitteeSelectionsFunc   func(context.Context, []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error)
	SubmitBeaconCommitteeSubscriptionsFunc func(ctx context.Context, subscriptions []*eth2v1.BeaconCommitteeSubscription) error
	AggregateAttestationFunc               func(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error)
	AggregateAttestationV2Func             func(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2spec.VersionedAttestation, error)
	SubmitAggregateAttestationsFunc        func(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error
	SubmitAggregateAttestationsV2Func      func(ctx context.Context, aggregateAndProofs *eth2api.SubmitAggregateAttestationsOpts) error
	SyncCommitteeDutiesFunc                func(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
	SubmitSyncCommitteeMessagesFunc        func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error
	SubmitSyncCommitteeContributionsFunc   func(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error
	SyncCommitteeContributionFunc          func(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	SubmitSyncCommitteeSubscriptionsFunc   func(ctx context.Context, subscriptions []*eth2v1.SyncCommitteeSubscription) error
	SubmitProposalPreparationsFunc         func(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error
	ForkScheduleFunc                       func(context.Context, *eth2api.ForkScheduleOpts) ([]*eth2p0.Fork, error)
	ProposerConfigFunc                     func(context.Context) (*eth2exp.ProposerConfigResponse, error)
	NodeVersionFunc                        func(context.Context, *eth2api.NodeVersionOpts) (*eth2api.Response[string], error)
}

func (m Mock) AggregateAttestation(ctx context.Context, opts *eth2api.AggregateAttestationOpts) (*eth2api.Response[*eth2p0.Attestation], error) {
	aggAtt, err := m.AggregateAttestationFunc(ctx, opts.Slot, opts.AttestationDataRoot)
	if err != nil {
		return nil, err
	}

	return wrapResponse(aggAtt), nil
}

func (m Mock) AggregateAttestationV2(ctx context.Context, opts *eth2api.AggregateAttestationOpts) (*eth2api.Response[*eth2spec.VersionedAttestation], error) {
	aggAtt, err := m.AggregateAttestationV2Func(ctx, opts.Slot, opts.AttestationDataRoot)
	if err != nil {
		return nil, err
	}

	return wrapResponse(aggAtt), nil
}

func (m Mock) AttestationData(ctx context.Context, opts *eth2api.AttestationDataOpts) (*eth2api.Response[*eth2p0.AttestationData], error) {
	attData, err := m.AttestationDataFunc(ctx, opts.Slot, opts.CommitteeIndex)
	if err != nil {
		return nil, err
	}

	return wrapResponse(attData), nil
}

func (m Mock) AttesterDuties(ctx context.Context, opts *eth2api.AttesterDutiesOpts) (*eth2api.Response[[]*eth2v1.AttesterDuty], error) {
	duties, err := m.AttesterDutiesFunc(ctx, opts.Epoch, opts.Indices)
	if err != nil {
		return nil, err
	}

	return wrapResponseWithMetadata(duties), nil
}

func (m Mock) Proposal(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.Response[*eth2api.VersionedProposal], error) {
	block, err := m.ProposalFunc(ctx, opts)
	if err != nil {
		return nil, err
	}

	return wrapResponse(block), nil
}

func (m Mock) SubmitBlindedProposal(ctx context.Context, block *eth2api.SubmitBlindedProposalOpts) error {
	return m.SubmitBlindedProposalFunc(ctx, block)
}

func (m Mock) ForkSchedule(ctx context.Context, opts *eth2api.ForkScheduleOpts) (*eth2api.Response[[]*eth2p0.Fork], error) {
	schedule, err := m.ForkScheduleFunc(ctx, opts)
	if err != nil {
		return nil, err
	}

	return wrapResponse(schedule), nil
}

func (m Mock) NodeSyncing(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2api.Response[*eth2v1.SyncState], error) {
	schedule, err := m.NodeSyncingFunc(ctx, opts)
	if err != nil {
		return nil, err
	}

	return wrapResponse(schedule), nil
}

func (m Mock) SubmitProposal(ctx context.Context, block *eth2api.SubmitProposalOpts) error {
	return m.SubmitProposalFunc(ctx, block)
}

func (m Mock) ProposerDuties(ctx context.Context, opts *eth2api.ProposerDutiesOpts) (*eth2api.Response[[]*eth2v1.ProposerDuty], error) {
	duties, err := m.ProposerDutiesFunc(ctx, opts.Epoch, opts.Indices)
	if err != nil {
		return nil, err
	}

	return wrapResponseWithMetadata(duties), nil
}

func (m Mock) SignedBeaconBlock(ctx context.Context, opts *eth2api.SignedBeaconBlockOpts) (*eth2api.Response[*eth2spec.VersionedSignedBeaconBlock], error) {
	block, err := m.SignedBeaconBlockFunc(ctx, opts.Block)
	if err != nil {
		return nil, err
	}

	return wrapResponse(block), nil
}

func (m Mock) SyncCommitteeContribution(ctx context.Context, opts *eth2api.SyncCommitteeContributionOpts) (*eth2api.Response[*altair.SyncCommitteeContribution], error) {
	contrib, err := m.SyncCommitteeContributionFunc(ctx, opts.Slot, opts.SubcommitteeIndex, opts.BeaconBlockRoot)
	if err != nil {
		return nil, err
	}

	return wrapResponse(contrib), nil
}

func (m Mock) SyncCommitteeDuties(ctx context.Context, opts *eth2api.SyncCommitteeDutiesOpts) (*eth2api.Response[[]*eth2v1.SyncCommitteeDuty], error) {
	duties, err := m.SyncCommitteeDutiesFunc(ctx, opts.Epoch, opts.Indices)
	if err != nil {
		return nil, err
	}

	return wrapResponse(duties), nil
}

func (m Mock) Validators(ctx context.Context, opts *eth2api.ValidatorsOpts) (*eth2api.Response[map[eth2p0.ValidatorIndex]*eth2v1.Validator], error) {
	vals, err := m.ValidatorsFunc(ctx, opts)
	if err != nil {
		return nil, err
	}

	return wrapResponse(vals), nil
}

func (Mock) SetValidatorCache(func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error)) {
	// Ignore this, only rely on WithValidator functional option.
}

func (m Mock) ActiveValidators(ctx context.Context) (eth2wrap.ActiveValidators, error) {
	active, _, err := m.CachedValidatorsFunc(ctx)
	return active, err
}

func (m Mock) CompleteValidators(ctx context.Context) (eth2wrap.CompleteValidators, error) {
	_, complete, err := m.CachedValidatorsFunc(ctx)
	return complete, err
}

func (m Mock) Genesis(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
	genesis, err := m.GenesisFunc(ctx, opts)
	if err != nil {
		return nil, err
	}

	return wrapResponse(genesis), nil
}

// Deprecated: use BlockAttestationsV2(ctx context.Context, stateID string) ([]*spec.VersionedAttestation, error)
func (m Mock) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	return m.BlockAttestationsFunc(ctx, stateID)
}

func (m Mock) BlockAttestationsV2(ctx context.Context, stateID string) ([]*eth2spec.VersionedAttestation, error) {
	return m.BlockAttestationsV2Func(ctx, stateID)
}

func (m Mock) BeaconStateCommittees(ctx context.Context, slot uint64) ([]*statecomm.StateCommittee, error) {
	return m.BeaconStateCommitteesFunc(ctx, slot)
}

func (m Mock) NodePeerCount(ctx context.Context) (int, error) {
	return m.NodePeerCountFunc(ctx)
}

func (m Mock) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	return m.SubmitAttestationsFunc(ctx, attestations)
}

func (m Mock) SubmitAttestationsV2(ctx context.Context, attestations *eth2api.SubmitAttestationsOpts) error {
	return m.SubmitAttestationsV2Func(ctx, attestations)
}

func (m Mock) SubmitVoluntaryExit(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error {
	return m.SubmitVoluntaryExitFunc(ctx, exit)
}

func (m Mock) ValidatorsByPubKey(ctx context.Context, stateID string, validatorPubKeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return m.ValidatorsByPubKeyFunc(ctx, stateID, validatorPubKeys)
}

func (m Mock) SubmitValidatorRegistrations(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
	return m.SubmitValidatorRegistrationsFunc(ctx, registrations)
}

func (m Mock) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	return m.AggregateBeaconCommitteeSelectionsFunc(ctx, selections)
}

func (m Mock) AggregateSyncCommitteeSelections(ctx context.Context, selections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	return m.AggregateSyncCommitteeSelectionsFunc(ctx, selections)
}

func (m Mock) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2v1.BeaconCommitteeSubscription) error {
	return m.SubmitBeaconCommitteeSubscriptionsFunc(ctx, subscriptions)
}

func (m Mock) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
	return m.SubmitAggregateAttestationsFunc(ctx, aggregateAndProofs)
}

func (m Mock) SubmitAggregateAttestationsV2(ctx context.Context, aggregateAndProofs *eth2api.SubmitAggregateAttestationsOpts) error {
	return m.SubmitAggregateAttestationsV2Func(ctx, aggregateAndProofs)
}

func (m Mock) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	return m.SubmitSyncCommitteeMessagesFunc(ctx, messages)
}

func (m Mock) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	return m.SubmitSyncCommitteeContributionsFunc(ctx, contributionAndProofs)
}

func (m Mock) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2v1.SyncCommitteeSubscription) error {
	return m.SubmitSyncCommitteeSubscriptionsFunc(ctx, subscriptions)
}

func (m Mock) SubmitProposalPreparations(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
	return m.SubmitProposalPreparationsFunc(ctx, preparations)
}

func (m Mock) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	return m.SlotsPerEpochFunc(ctx)
}

func (m Mock) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	return m.ProposerConfigFunc(ctx)
}

func (m Mock) NodeVersion(ctx context.Context, opts *eth2api.NodeVersionOpts) (*eth2api.Response[string], error) {
	return m.NodeVersionFunc(ctx, opts)
}

func (Mock) SetForkVersion([4]byte) {
	// This function is a no-op, since we mock the fork version at beaconmock initialization.
}

func (Mock) Name() string {
	return "beacon-mock"
}

func (m Mock) Address() string {
	return "http://" + m.httpServer.Addr
}

func (m Mock) IsActive() bool {
	return m.IsActiveFunc()
}

func (m Mock) IsSynced() bool {
	return m.IsSyncedFunc()
}

func (m Mock) Close() error {
	m.headProducer.Close()

	err := m.httpServer.Close()
	if err != nil {
		return errors.Wrap(err, "close server")
	}

	return nil
}

// wrapResponse wraps the provided data into an API Response and returns the response.
func wrapResponse[T any](data T) *eth2api.Response[T] {
	return &eth2api.Response[T]{Data: data}
}

// wrapResponseWithMetadata wraps the provided data, adds metadata into an API Response and returns the response.
func wrapResponseWithMetadata[T any](data T) *eth2api.Response[T] {
	return &eth2api.Response[T]{
		Data: data,
		Metadata: map[string]any{
			"execution_optimistic": false,
			"dependent_root":       eth2p0.Root{},
		},
	}
}
