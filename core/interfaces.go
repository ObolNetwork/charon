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

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Scheduler triggers the start of a duty workflow.
type Scheduler interface {
	// Subscribe registers a callback for fetching a duty.
	Subscribe(func(context.Context, Duty, DutyDefinitionSet) error)

	// GetDutyDefinition returns the definition set for a duty if already resolved.
	GetDutyDefinition(context.Context, Duty) (DutyDefinitionSet, error)
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
}

// DutyDB persists unsigned duty data sets and makes it available for querying. It also acts
// as slashing database.
type DutyDB interface {
	// Store stores the unsigned duty data set.
	Store(context.Context, Duty, UnsignedDataSet) error

	// AwaitBeaconBlock blocks and returns the proposed beacon block
	// for the slot when available.
	AwaitBeaconBlock(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)

	// AwaitAttestation blocks and returns the attestation data
	// for the slot and committee index when available.
	AwaitAttestation(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)

	// PubKeyByAttestation returns the validator PubKey for the provided attestation data
	// slot, committee index and validator committee index. This allows mapping of attestation
	// data response to validator.
	PubKeyByAttestation(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error)
}

// Consensus comes to consensus on proposed duty data.
type Consensus interface {
	// Propose triggers consensus game of the proposed duty unsigned data set.
	Propose(context.Context, Duty, UnsignedDataSet) error

	// Subscribe registers a callback for resolved (reached consensus) duty unsigned data set.
	Subscribe(func(context.Context, Duty, UnsignedDataSet) error)
}

// ValidatorAPI provides a beacon node API to validator clients. It serves duty data from the
// DutyDB and stores partial signed data in the ParSigDB.
type ValidatorAPI interface {
	// RegisterAwaitBeaconBlock registers a function to query a unsigned beacon block by slot.
	RegisterAwaitBeaconBlock(func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error))

	// RegisterAwaitAttestation registers a function to query attestation data.
	RegisterAwaitAttestation(func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error))

	// RegisterPubKeyByAttestation registers a function to query validator by attestation.
	RegisterPubKeyByAttestation(func(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error))

	// RegisterGetDutyDefinition registers a function to query duty definitions.
	RegisterGetDutyDefinition(func(context.Context, Duty) (DutyDefinitionSet, error))

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
	// partially signed duty is reached for a DV.
	SubscribeThreshold(func(context.Context, Duty, PubKey, []ParSignedData) error)
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
	// Aggregate aggregates the partially signed duty data for the DV.
	Aggregate(context.Context, Duty, PubKey, []ParSignedData) error

	// Subscribe registers a callback for aggregated signed duty data.
	Subscribe(func(context.Context, Duty, PubKey, SignedData) error)
}

// AggSigDB persists aggregated signed duty data.
type AggSigDB interface {
	// Store stores aggregated signed duty data.
	Store(context.Context, Duty, PubKey, SignedData) error

	// Await blocks and returns the aggregated signed duty data when available.
	Await(context.Context, Duty, PubKey) (SignedData, error)
}

// Broadcaster broadcasts aggregated signed duty data to the beacon node.
type Broadcaster interface {
	Broadcast(context.Context, Duty, PubKey, SignedData) error
}

// wireFuncs defines the core workflow components as a list input and output functions
// instead as interfaces, since functions are easier to wrap than interfaces.
type wireFuncs struct {
	SchedulerSubscribe              func(func(context.Context, Duty, DutyDefinitionSet) error)
	SchedulerGetDutyDefinition      func(context.Context, Duty) (DutyDefinitionSet, error)
	FetcherFetch                    func(context.Context, Duty, DutyDefinitionSet) error
	FetcherSubscribe                func(func(context.Context, Duty, UnsignedDataSet) error)
	FetcherRegisterAggSigDB         func(func(context.Context, Duty, PubKey) (SignedData, error))
	ConsensusPropose                func(context.Context, Duty, UnsignedDataSet) error
	ConsensusSubscribe              func(func(context.Context, Duty, UnsignedDataSet) error)
	DutyDBStore                     func(context.Context, Duty, UnsignedDataSet) error
	DutyDBAwaitBeaconBlock          func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)
	DutyDBAwaitAttestation          func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)
	DutyDBPubKeyByAttestation       func(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error)
	VAPIRegisterAwaitAttestation    func(func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error))
	VAPIRegisterAwaitBeaconBlock    func(func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error))
	VAPIRegisterGetDutyDefinition   func(func(context.Context, Duty) (DutyDefinitionSet, error))
	VAPIRegisterPubKeyByAttestation func(func(ctx context.Context, slot, commIdx, valCommIdx int64) (PubKey, error))
	VAPISubscribe                   func(func(context.Context, Duty, ParSignedDataSet) error)
	ParSigDBStoreInternal           func(context.Context, Duty, ParSignedDataSet) error
	ParSigDBStoreExternal           func(context.Context, Duty, ParSignedDataSet) error
	ParSigDBSubscribeInternal       func(func(context.Context, Duty, ParSignedDataSet) error)
	ParSigDBSubscribeThreshold      func(func(context.Context, Duty, PubKey, []ParSignedData) error)
	ParSigExBroadcast               func(context.Context, Duty, ParSignedDataSet) error
	ParSigExSubscribe               func(func(context.Context, Duty, ParSignedDataSet) error)
	SigAggAggregate                 func(context.Context, Duty, PubKey, []ParSignedData) error
	SigAggSubscribe                 func(func(context.Context, Duty, PubKey, SignedData) error)
	AggSigDBStore                   func(context.Context, Duty, PubKey, SignedData) error
	AggSigDBAwait                   func(context.Context, Duty, PubKey) (SignedData, error)
	BroadcasterBroadcast            func(context.Context, Duty, PubKey, SignedData) error
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
		SchedulerSubscribe:              sched.Subscribe,
		SchedulerGetDutyDefinition:      sched.GetDutyDefinition,
		FetcherFetch:                    fetch.Fetch,
		FetcherSubscribe:                fetch.Subscribe,
		FetcherRegisterAggSigDB:         fetch.RegisterAggSigDB,
		ConsensusPropose:                cons.Propose,
		ConsensusSubscribe:              cons.Subscribe,
		DutyDBStore:                     dutyDB.Store,
		DutyDBAwaitAttestation:          dutyDB.AwaitAttestation,
		DutyDBAwaitBeaconBlock:          dutyDB.AwaitBeaconBlock,
		DutyDBPubKeyByAttestation:       dutyDB.PubKeyByAttestation,
		VAPIRegisterAwaitBeaconBlock:    vapi.RegisterAwaitBeaconBlock,
		VAPIRegisterAwaitAttestation:    vapi.RegisterAwaitAttestation,
		VAPIRegisterGetDutyDefinition:   vapi.RegisterGetDutyDefinition,
		VAPIRegisterPubKeyByAttestation: vapi.RegisterPubKeyByAttestation,
		VAPISubscribe:                   vapi.Subscribe,
		ParSigDBStoreInternal:           parSigDB.StoreInternal,
		ParSigDBStoreExternal:           parSigDB.StoreExternal,
		ParSigDBSubscribeInternal:       parSigDB.SubscribeInternal,
		ParSigDBSubscribeThreshold:      parSigDB.SubscribeThreshold,
		ParSigExBroadcast:               parSigEx.Broadcast,
		ParSigExSubscribe:               parSigEx.Subscribe,
		SigAggAggregate:                 sigAgg.Aggregate,
		SigAggSubscribe:                 sigAgg.Subscribe,
		AggSigDBStore:                   aggSigDB.Store,
		AggSigDBAwait:                   aggSigDB.Await,
		BroadcasterBroadcast:            bcast.Broadcast,
	}

	for _, opt := range opts {
		opt(&w)
	}

	w.SchedulerSubscribe(w.FetcherFetch)
	w.FetcherSubscribe(w.ConsensusPropose)
	w.FetcherRegisterAggSigDB(w.AggSigDBAwait)
	w.ConsensusSubscribe(w.DutyDBStore)
	w.VAPIRegisterAwaitBeaconBlock(w.DutyDBAwaitBeaconBlock)
	w.VAPIRegisterAwaitAttestation(w.DutyDBAwaitAttestation)
	w.VAPIRegisterGetDutyDefinition(w.SchedulerGetDutyDefinition)
	w.VAPIRegisterPubKeyByAttestation(w.DutyDBPubKeyByAttestation)
	w.VAPISubscribe(w.ParSigDBStoreInternal)
	w.ParSigDBSubscribeInternal(w.ParSigExBroadcast)
	w.ParSigExSubscribe(w.ParSigDBStoreExternal)
	w.ParSigDBSubscribeThreshold(w.SigAggAggregate)
	w.SigAggSubscribe(w.AggSigDBStore)
	w.SigAggSubscribe(w.BroadcasterBroadcast)
}
