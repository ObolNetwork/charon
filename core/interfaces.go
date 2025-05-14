// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/protocol"
)

//go:generate mockery --name=Consensus --output=mocks --outpkg=mocks --case=underscore

// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
	// SubscribeDuties subscribes a callback function for triggered duties.
	SubscribeDuties(func(context.Context, Duty, DutyDefinitionSet) error)

	// SubscribeSlots subscribes a callback function for triggered slots.
	SubscribeSlots(func(context.Context, Slot) error)

	// GetDutyDefinition returns the definition set for a duty if already resolved.
	GetDutyDefinition(Duty) (DutyDefinitionSet, error)
}

// Fetcher fetches proposed unsigned duty data.
type Fetcher interface {
	// Fetch triggers fetching of a proposed duty data set.
	Fetch(context.Context, Duty, DutyDefinitionSet) error

	// Subscribe registers a callback for proposed unsigned duty data sets.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)

	// RegisterAggSigDB registers a function to get resolved aggregated
	// signed data from the AggSigDB (e.g., randao reveals).
	RegisterAggSigDB(func(context.Context, Duty, PubKey) (SignedData, error))

	// RegisterAwaitAttData registers a function to get attestation data from DutyDB.
	RegisterAwaitAttData(func(ctx context.Context, slot uint64, commIdx uint64) (*eth2p0.AttestationData, error))
}

// DutyDB persists unsigned duty data sets and makes it available for querying. It also acts as slashing database.
type DutyDB interface {
	// Store stores the unsigned duty data set.
	Store(context.Context, Duty, UnsignedDataSet) error

	// AwaitProposal blocks and returns the proposed beacon block
	// for the slot when available.
	AwaitProposal(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error)

	// AwaitAttestation blocks and returns the attestation data
	// for the slot and committee index when available.
	AwaitAttestation(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error)

	// PubKeyByAttestation returns the validator PubKey for the provided attestation data
	// slot, committee index and validator committee index. This allows mapping of attestation
	// data response to validator.
	PubKeyByAttestation(ctx context.Context, slot, commIdx, valCommIdx uint64) (PubKey, error)

	// PubKeyByAttestationV2 returns the validator PubKey for the provided attestation data
	// slot, committee index and validator index. This allows mapping of attestation
	// data response to validator.
	PubKeyByAttestationV2(ctx context.Context, slot, commIdx, valIdx uint64) (PubKey, error)

	// AwaitAggAttestation blocks and returns the aggregated attestation for the slot
	// and attestation when available.
	AwaitAggAttestation(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)

	// AwaitAggAttestationV2 blocks and returns the aggregated attestation for the slot
	// and attestation when available.
	AwaitAggAttestationV2(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2spec.VersionedAttestation, error)

	// AwaitSyncContribution blocks and returns the sync committee contribution data for the slot and
	// the subcommittee and the beacon block root when available.
	AwaitSyncContribution(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
}

// P2PProtocol defines an arbitrary libp2p protocol.
type P2PProtocol interface {
	// ProtocolID returns the protocol ID.
	ProtocolID() protocol.ID

	// Start registers libp2p handler and runs internal routines until the context is cancelled.
	// The protocol must be unregistered when the context is cancelled.
	Start(context.Context)
}

// Consensus comes to consensus on proposed duty data.
type Consensus interface {
	P2PProtocol

	// Participate run the duty's consensus instance without a proposed value (if Propose not called yet).
	Participate(context.Context, Duty) error

	// Propose provides the consensus instance proposed value (and run it if Participate not called yet).
	Propose(context.Context, Duty, UnsignedDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty unsigned data set.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)
}

// ConsensusController manages consensus instances.
type ConsensusController interface {
	// Start starts the consensus controller lifecycle.
	// The function is not thread safe, must be called once.
	Start(context.Context)

	// DefaultConsensus returns the default consensus instance.
	// The default consensus must be QBFT v2.0, since it is supported by all charon versions.
	// It is used for Priority protocol as well as the fallback protocol when no other protocol is selected.
	// Multiple calls to DefaultConsensus must return the same instance.
	DefaultConsensus() Consensus

	// CurrentConsensus returns the currently selected consensus instance.
	// The instance is selected by the Priority protocol and can be changed by SetCurrentConsensusForProtocol().
	// Before SetCurrentConsensusForProtocol() is called, CurrentConsensus() points to DefaultConsensus().
	CurrentConsensus() Consensus

	// SetCurrentConsensusForProtocol handles Priority protocol outcome and changes the CurrentConsensus() accordingly.
	// The function is not thread safe.
	SetCurrentConsensusForProtocol(context.Context, protocol.ID) error
}

// ValidatorAPI provides a beacon node API to validator clients. It serves duty data from the DutyDB and stores partial signed data in the ParSigDB.
type ValidatorAPI interface {
	// RegisterAwaitProposal registers a function to query unsigned beacon block proposals by providing the slot.
	RegisterAwaitProposal(func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error))

	// RegisterAwaitAttestation registers a function to query attestation data.
	RegisterAwaitAttestation(func(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error))

	// RegisterAwaitSyncContribution registers a function to query sync contribution data.
	RegisterAwaitSyncContribution(func(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error))

	// RegisterPubKeyByAttestation registers a function to query validator by attestation.
	RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx uint64) (PubKey, error))

	// RegisterPubKeyByAttestationV2 registers a function to query validator by attestation.
	RegisterPubKeyByAttestationV2(func(ctx context.Context, slot, commIdx, valIdx uint64) (PubKey, error))

	// RegisterGetDutyDefinition registers a function to query duty definitions.
	RegisterGetDutyDefinition(func(Duty) (DutyDefinitionSet, error))

	// RegisterAwaitAggAttestation registers a function to query aggregated attestation.
	RegisterAwaitAggAttestation(fn func(ctx context.Context, slot uint64, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error))

	// RegisterAwaitAggAttestation registers a function to query aggregated attestation.
	RegisterAwaitAggAttestationV2(fn func(ctx context.Context, slot uint64, attestationDataRoot eth2p0.Root) (*eth2spec.VersionedAttestation, error))

	// RegisterAwaitAggSigDB registers a function to query aggregated signed data from aggSigDB.
	RegisterAwaitAggSigDB(func(context.Context, Duty, PubKey) (SignedData, error))

	// Subscribe registers a function to store partially signed data sets.
	Subscribe(func(context.Context, Duty, ParSignedDataSet) error)
}

// ParSigDB persists partial signatures and sends them to the
// partial signature exchange and aggregation.
type ParSigDB interface {
	// StoreInternal stores an internally received partially signed duty data set.
	StoreInternal(context.Context, Duty, ParSignedDataSet) error

	// StoreExternal stores an externally received partially signed duty data set.
	StoreExternal(context.Context, Duty, ParSignedDataSet) error

	// SubscribeInternal registers a callback when an internal
	// partially signed duty set is stored.
	SubscribeInternal(func(context.Context, Duty, ParSignedDataSet) error)

	// SubscribeThreshold registers a callback when *threshold*
	// partially signed duty is reached for the set of DVs.
	SubscribeThreshold(func(context.Context, Duty, map[PubKey][]ParSignedData) error)
}

// ParSigEx exchanges partially signed duty data sets.
type ParSigEx interface {
	// Broadcast broadcasts the partially signed duty data set to all peers.
	Broadcast(context.Context, Duty, ParSignedDataSet) error

	// Subscribe registers a callback when a partially signed duty set
	// is received from a peer.
	Subscribe(func(context.Context, Duty, ParSignedDataSet) error)
}

// SigAgg aggregates threshold partial signatures.
type SigAgg interface {
	// Aggregate aggregates the partially signed duty datas for the set of DVs.
	Aggregate(context.Context, Duty, map[PubKey][]ParSignedData) error

	// Subscribe registers a callback for aggregated signed duty data set.
	Subscribe(func(context.Context, Duty, SignedDataSet) error)
}

// AggSigDB persists aggregated signed duty data.
type AggSigDB interface {
	// Store stores aggregated signed duty data set.
	Store(context context.Context, duty Duty, data SignedDataSet) error

	// Await blocks and returns the aggregated signed duty data when available.
	Await(context context.Context, duty Duty, pubKey PubKey) (SignedData, error)

	// Run runs AggSigDB lifecycle until context is cancelled.
	Run(context context.Context)
}

// Broadcaster broadcasts aggregated signed duty data set to the beacon node.
type Broadcaster interface {
	Broadcast(context.Context, Duty, SignedDataSet) error
}

// InclusionChecker checks whether submitted duties have been included on-chain.
// TODO(corver): Merge this with tracker below as a compose multi tracker.
type InclusionChecker interface {
	// Submitted is called when a duty set has been submitted.
	Submitted(Duty, SignedDataSet) error
}

// Tracker sends core component events for further analysis and instrumentation.
type Tracker interface {
	// FetcherFetched sends Fetcher component's events to tracker.
	FetcherFetched(Duty, DutyDefinitionSet, error)

	// ConsensusProposed sends Consensus component's events to tracker.
	ConsensusProposed(Duty, UnsignedDataSet, error)

	// DutyDBStored sends DutyDB component's store events to tracker.
	DutyDBStored(Duty, UnsignedDataSet, error)

	// ParSigDBStoredInternal sends ParSigDB component's store internal events to tracker.
	ParSigDBStoredInternal(Duty, ParSignedDataSet, error)

	// ParSigExBroadcasted sends ParSigEx component's broadcast events to tracker.
	ParSigExBroadcasted(Duty, ParSignedDataSet, error)

	// ParSigDBStoredExternal sends ParSigDB component's store external events to tracker.
	ParSigDBStoredExternal(Duty, ParSignedDataSet, error)

	// SigAggAggregated sends SigAgg component's aggregate events to tracker.
	SigAggAggregated(Duty, map[PubKey][]ParSignedData, error)

	// AggSigDBStored sends AggSigDB component's store events to tracker.
	AggSigDBStored(Duty, SignedDataSet, error)

	// BroadcasterBroadcast sends Broadcaster component's broadcast events to tracker.
	BroadcasterBroadcast(Duty, SignedDataSet, error)

	// InclusionChecked sends InclusionChecker component's check events to tracker.
	InclusionChecked(Duty, PubKey, SignedData, error)
}

// wireFuncs defines the core workflow components as a list of input and output functions
// instead as interfaces, since functions are easier to wrap than interfaces.
type wireFuncs struct {
	SchedulerSubscribeDuties          func(func(context.Context, Duty, DutyDefinitionSet) error)
	SchedulerSubscribeSlots           func(func(context.Context, Slot) error)
	SchedulerGetDutyDefinition        func(Duty) (DutyDefinitionSet, error)
	FetcherFetch                      func(context.Context, Duty, DutyDefinitionSet) error
	FetcherSubscribe                  func(func(context.Context, Duty, UnsignedDataSet) error)
	FetcherRegisterAggSigDB           func(func(context.Context, Duty, PubKey) (SignedData, error))
	FetcherRegisterAwaitAttData       func(func(ctx context.Context, slot uint64, commIdx uint64) (*eth2p0.AttestationData, error))
	ConsensusParticipate              func(context.Context, Duty) error
	ConsensusPropose                  func(context.Context, Duty, UnsignedDataSet) error
	ConsensusSubscribe                func(func(context.Context, Duty, UnsignedDataSet) error)
	DutyDBStore                       func(context.Context, Duty, UnsignedDataSet) error
	DutyDBAwaitProposal               func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error)
	DutyDBAwaitAttestation            func(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error)
	DutyDBPubKeyByAttestation         func(ctx context.Context, slot, commIdx, valCommIdx uint64) (PubKey, error)
	DutyDBPubKeyByAttestationV2       func(ctx context.Context, slot, commIdx, valIdx uint64) (PubKey, error)
	DutyDBAwaitAggAttestation         func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)
	DutyDBAwaitAggAttestationV2       func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2spec.VersionedAttestation, error)
	DutyDBAwaitSyncContribution       func(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	VAPIRegisterAwaitAttestation      func(func(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error))
	VAPIRegisterAwaitSyncContribution func(func(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error))
	VAPIRegisterAwaitProposal         func(func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error))
	VAPIRegisterGetDutyDefinition     func(func(Duty) (DutyDefinitionSet, error))
	VAPIRegisterPubKeyByAttestation   func(func(ctx context.Context, slot, commIdx, valCommIdx uint64) (PubKey, error))
	VAPIRegisterPubKeyByAttestationV2 func(func(ctx context.Context, slot, commIdx, valIdx uint64) (PubKey, error))
	VAPIRegisterAwaitAggAttestation   func(func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error))
	VAPIRegisterAwaitAggAttestationV2 func(func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2spec.VersionedAttestation, error))
	VAPIRegisterAwaitAggSigDB         func(func(context.Context, Duty, PubKey) (SignedData, error))
	VAPISubscribe                     func(func(context.Context, Duty, ParSignedDataSet) error)
	ParSigDBStoreInternal             func(context.Context, Duty, ParSignedDataSet) error
	ParSigDBStoreExternal             func(context.Context, Duty, ParSignedDataSet) error
	ParSigDBSubscribeInternal         func(func(context.Context, Duty, ParSignedDataSet) error)
	ParSigDBSubscribeThreshold        func(func(context.Context, Duty, map[PubKey][]ParSignedData) error)
	ParSigExBroadcast                 func(context.Context, Duty, ParSignedDataSet) error
	ParSigExSubscribe                 func(func(context.Context, Duty, ParSignedDataSet) error)
	SigAggAggregate                   func(context.Context, Duty, map[PubKey][]ParSignedData) error
	SigAggSubscribe                   func(func(context.Context, Duty, SignedDataSet) error)
	AggSigDBStore                     func(context.Context, Duty, SignedDataSet) error
	AggSigDBAwait                     func(context.Context, Duty, PubKey) (SignedData, error)
	BroadcasterBroadcast              func(context.Context, Duty, SignedDataSet) error
}

// WireOption defines a functional option to configure wiring.
type WireOption func(*wireFuncs)

// Wire wires the workflow components together.
func Wire(sched Scheduler,
	fetch Fetcher,
	cons Consensus,
	dutyDB DutyDB,
	vapi ValidatorAPI,
	parSigDB ParSigDB,
	parSigEx ParSigEx,
	sigAgg SigAgg,
	aggSigDB AggSigDB,
	bcast Broadcaster,
	opts ...WireOption,
) {
	w := wireFuncs{
		SchedulerSubscribeDuties:          sched.SubscribeDuties,
		SchedulerSubscribeSlots:           sched.SubscribeSlots,
		SchedulerGetDutyDefinition:        sched.GetDutyDefinition,
		FetcherFetch:                      fetch.Fetch,
		FetcherSubscribe:                  fetch.Subscribe,
		FetcherRegisterAggSigDB:           fetch.RegisterAggSigDB,
		FetcherRegisterAwaitAttData:       fetch.RegisterAwaitAttData,
		ConsensusParticipate:              cons.Participate,
		ConsensusPropose:                  cons.Propose,
		ConsensusSubscribe:                cons.Subscribe,
		DutyDBStore:                       dutyDB.Store,
		DutyDBAwaitAttestation:            dutyDB.AwaitAttestation,
		DutyDBAwaitProposal:               dutyDB.AwaitProposal,
		DutyDBPubKeyByAttestation:         dutyDB.PubKeyByAttestation,
		DutyDBPubKeyByAttestationV2:       dutyDB.PubKeyByAttestationV2,
		DutyDBAwaitAggAttestation:         dutyDB.AwaitAggAttestation,
		DutyDBAwaitAggAttestationV2:       dutyDB.AwaitAggAttestationV2,
		DutyDBAwaitSyncContribution:       dutyDB.AwaitSyncContribution,
		VAPIRegisterAwaitProposal:         vapi.RegisterAwaitProposal,
		VAPIRegisterAwaitAttestation:      vapi.RegisterAwaitAttestation,
		VAPIRegisterAwaitSyncContribution: vapi.RegisterAwaitSyncContribution,
		VAPIRegisterGetDutyDefinition:     vapi.RegisterGetDutyDefinition,
		VAPIRegisterPubKeyByAttestation:   vapi.RegisterPubKeyByAttestation,
		VAPIRegisterPubKeyByAttestationV2: vapi.RegisterPubKeyByAttestationV2,
		VAPIRegisterAwaitAggAttestation:   vapi.RegisterAwaitAggAttestation,
		VAPIRegisterAwaitAggAttestationV2: vapi.RegisterAwaitAggAttestationV2,
		VAPIRegisterAwaitAggSigDB:         vapi.RegisterAwaitAggSigDB,
		VAPISubscribe:                     vapi.Subscribe,
		ParSigDBStoreInternal:             parSigDB.StoreInternal,
		ParSigDBStoreExternal:             parSigDB.StoreExternal,
		ParSigDBSubscribeInternal:         parSigDB.SubscribeInternal,
		ParSigDBSubscribeThreshold:        parSigDB.SubscribeThreshold,
		ParSigExBroadcast:                 parSigEx.Broadcast,
		ParSigExSubscribe:                 parSigEx.Subscribe,
		SigAggAggregate:                   sigAgg.Aggregate,
		SigAggSubscribe:                   sigAgg.Subscribe,
		AggSigDBStore:                     aggSigDB.Store,
		AggSigDBAwait:                     aggSigDB.Await,
		BroadcasterBroadcast:              bcast.Broadcast,
	}

	for _, opt := range opts {
		opt(&w)
	}

	w.SchedulerSubscribeDuties(w.FetcherFetch)
	w.SchedulerSubscribeDuties(func(ctx context.Context, duty Duty, _ DutyDefinitionSet) error {
		return w.ConsensusParticipate(ctx, duty)
	})
	w.FetcherSubscribe(w.ConsensusPropose)
	w.FetcherRegisterAggSigDB(w.AggSigDBAwait)
	w.FetcherRegisterAwaitAttData(w.DutyDBAwaitAttestation)
	w.ConsensusSubscribe(w.DutyDBStore)
	w.VAPIRegisterAwaitProposal(w.DutyDBAwaitProposal)
	w.VAPIRegisterAwaitAttestation(w.DutyDBAwaitAttestation)
	w.VAPIRegisterAwaitSyncContribution(w.DutyDBAwaitSyncContribution)
	w.VAPIRegisterGetDutyDefinition(w.SchedulerGetDutyDefinition)
	w.VAPIRegisterPubKeyByAttestation(w.DutyDBPubKeyByAttestation)
	w.VAPIRegisterPubKeyByAttestationV2(w.DutyDBPubKeyByAttestationV2)
	w.VAPIRegisterAwaitAggAttestation(w.DutyDBAwaitAggAttestation)
	w.VAPIRegisterAwaitAggAttestationV2(w.DutyDBAwaitAggAttestationV2)
	w.VAPIRegisterAwaitAggSigDB(w.AggSigDBAwait)
	w.VAPISubscribe(w.ParSigDBStoreInternal)
	w.ParSigDBSubscribeInternal(w.ParSigExBroadcast)
	w.ParSigExSubscribe(w.ParSigDBStoreExternal)
	w.ParSigDBSubscribeThreshold(w.SigAggAggregate)
	w.SigAggSubscribe(w.AggSigDBStore)
	w.SigAggSubscribe(w.BroadcasterBroadcast)
}
