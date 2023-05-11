// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"fmt"
	"net/http"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
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
				Endpoint: "/eth/v1/beacon/genesis",
				Key:      "genesis_time",
				Value:    fmt.Sprint(genesis.Unix()),
			},
		},
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

	ActiveValidatorsFunc                   func(ctx context.Context) (eth2wrap.ActiveValidators, error)
	AttestationDataFunc                    func(context.Context, eth2p0.Slot, eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error)
	AttesterDutiesFunc                     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error)
	BlockAttestationsFunc                  func(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error)
	NodePeerCountFunc                      func(ctx context.Context) (int, error)
	BlindedBeaconBlockProposalFunc         func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error)
	BeaconBlockProposalFunc                func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error)
	SignedBeaconBlockFunc                  func(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error)
	ProposerDutiesFunc                     func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error)
	SubmitAttestationsFunc                 func(context.Context, []*eth2p0.Attestation) error
	SubmitBeaconBlockFunc                  func(context.Context, *eth2spec.VersionedSignedBeaconBlock) error
	SubmitBlindedBeaconBlockFunc           func(context.Context, *eth2api.VersionedSignedBlindedBeaconBlock) error
	SubmitVoluntaryExitFunc                func(context.Context, *eth2p0.SignedVoluntaryExit) error
	ValidatorsByPubKeyFunc                 func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	ValidatorsFunc                         func(context.Context, string, []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error)
	GenesisTimeFunc                        func(context.Context) (time.Time, error)
	NodeSyncingFunc                        func(context.Context) (*eth2v1.SyncState, error)
	SubmitValidatorRegistrationsFunc       func(context.Context, []*eth2api.VersionedSignedValidatorRegistration) error
	SlotsPerEpochFunc                      func(context.Context) (uint64, error)
	AggregateBeaconCommitteeSelectionsFunc func(context.Context, []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error)
	AggregateSyncCommitteeSelectionsFunc   func(context.Context, []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error)
	SubmitBeaconCommitteeSubscriptionsFunc func(ctx context.Context, subscriptions []*eth2v1.BeaconCommitteeSubscription) error
	AggregateAttestationFunc               func(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error)
	SubmitAggregateAttestationsFunc        func(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error
	SyncCommitteeDutiesFunc                func(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error)
	SubmitSyncCommitteeMessagesFunc        func(ctx context.Context, messages []*altair.SyncCommitteeMessage) error
	SubmitSyncCommitteeContributionsFunc   func(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error
	SyncCommitteeContributionFunc          func(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	SubmitSyncCommitteeSubscriptionsFunc   func(ctx context.Context, subscriptions []*eth2v1.SyncCommitteeSubscription) error
	SubmitProposalPreparationsFunc         func(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error
	ForkScheduleFunc                       func(context.Context) ([]*eth2p0.Fork, error)
}

func (Mock) SetValidatorCache(func(context.Context) (eth2wrap.ActiveValidators, error)) {
	// Ignore this, only rely on WithValidator functional option.
}

func (m Mock) ActiveValidators(ctx context.Context) (eth2wrap.ActiveValidators, error) {
	return m.ActiveValidatorsFunc(ctx)
}

func (m Mock) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	return m.BlockAttestationsFunc(ctx, stateID)
}

func (m Mock) NodePeerCount(ctx context.Context) (int, error) {
	return m.NodePeerCountFunc(ctx)
}

func (m Mock) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	return m.SubmitAttestationsFunc(ctx, attestations)
}

func (m Mock) SubmitBeaconBlock(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
	return m.SubmitBeaconBlockFunc(ctx, block)
}

func (m Mock) SubmitBlindedBeaconBlock(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
	return m.SubmitBlindedBeaconBlockFunc(ctx, block)
}

func (m Mock) SubmitVoluntaryExit(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error {
	return m.SubmitVoluntaryExitFunc(ctx, exit)
}

func (m Mock) AttestationData(ctx context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return m.AttestationDataFunc(ctx, slot, committeeIndex)
}

func (m Mock) BlindedBeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
	return m.BlindedBeaconBlockProposalFunc(ctx, slot, randaoReveal, graffiti)
}

func (m Mock) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2spec.VersionedBeaconBlock, error) {
	return m.BeaconBlockProposalFunc(ctx, slot, randaoReveal, graffiti)
}

func (m Mock) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return m.ProposerDutiesFunc(ctx, epoch, validatorIndices)
}

func (m Mock) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	return m.AttesterDutiesFunc(ctx, epoch, validatorIndices)
}

func (m Mock) Validators(ctx context.Context, stateID string, validatorIndices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return m.ValidatorsFunc(ctx, stateID, validatorIndices)
}

func (m Mock) ValidatorsByPubKey(ctx context.Context, stateID string, validatorPubKeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	return m.ValidatorsByPubKeyFunc(ctx, stateID, validatorPubKeys)
}

func (m Mock) GenesisTime(ctx context.Context) (time.Time, error) {
	return m.GenesisTimeFunc(ctx)
}

func (m Mock) NodeSyncing(ctx context.Context) (*eth2v1.SyncState, error) {
	return m.NodeSyncingFunc(ctx)
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

func (m Mock) AggregateAttestation(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error) {
	return m.AggregateAttestationFunc(ctx, slot, attestationDataRoot)
}

func (m Mock) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
	return m.SubmitAggregateAttestationsFunc(ctx, aggregateAndProofs)
}

func (m Mock) SyncCommitteeDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	return m.SyncCommitteeDutiesFunc(ctx, epoch, validatorIndices)
}

func (m Mock) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	return m.SubmitSyncCommitteeMessagesFunc(ctx, messages)
}

func (m Mock) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	return m.SubmitSyncCommitteeContributionsFunc(ctx, contributionAndProofs)
}

func (m Mock) SyncCommitteeContribution(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
	return m.SyncCommitteeContributionFunc(ctx, slot, subcommitteeIndex, beaconBlockRoot)
}

func (m Mock) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2v1.SyncCommitteeSubscription) error {
	return m.SubmitSyncCommitteeSubscriptionsFunc(ctx, subscriptions)
}

func (m Mock) SubmitProposalPreparations(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
	return m.SubmitProposalPreparationsFunc(ctx, preparations)
}

func (m Mock) SignedBeaconBlock(ctx context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
	return m.SignedBeaconBlockFunc(ctx, blockID)
}

func (m Mock) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	return m.SlotsPerEpochFunc(ctx)
}

func (m Mock) ForkSchedule(ctx context.Context) ([]*eth2p0.Fork, error) {
	return m.ForkScheduleFunc(ctx)
}

func (Mock) TekuProposerConfig(context.Context) (validatorapi.TekuProposerConfigResponse, error) {
	panic("implement me")
}

func (Mock) Name() string {
	return "beacon-mock"
}

func (m Mock) Address() string {
	return "http://" + m.httpServer.Addr
}

func (m Mock) Close() error {
	m.headProducer.Close()

	err := m.httpServer.Close()
	if err != nil {
		return errors.Wrap(err, "close server")
	}

	return nil
}
