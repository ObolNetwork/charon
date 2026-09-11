// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb

import (
	"bytes"
	"context"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

var (
	ErrStopped = errors.New("database stopped")

	// errNotAwaitable is returned when awaiting a duty family that is only stored and
	// broadcasted, never queried.
	errNotAwaitable = errors.New("duty aggregate is not awaitable")
)

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB(deadliner core.Deadliner) *MemDB {
	return &MemDB{
		generalDuties:  newAggStore[generalKey](),
		subCommDuties:  newAggStore[subCommKey](),
		propPrefDuties: newAggStore[propPrefKey](),
		commands:       make(chan writeCommand),
		queries:        make(chan readQuery),
		blockedQueries: []readQuery{},
		queryCallback:  func([]readQuery) {},
		quit:           make(chan struct{}),
		deadliner:      deadliner,
	}
}

// MemDB is a basic memory implementation of core.AggSigDB.
type MemDB struct {
	// Aggregates are stored per duty family, each keyed by the family's identity
	// and trimmed when the deadliner expires the duty.

	// generalDuties holds duties with a single message per duty and validator.
	generalDuties *aggStore[generalKey]
	// subCommDuties holds sync-committee aggregator duties, additionally keyed by
	// sync subcommittee index.
	subCommDuties *aggStore[subCommKey]
	// propPrefDuties holds proposer preferences, additionally keyed by the fields
	// that may legitimately change on resubmission. They are not awaitable, only broadcasted.
	propPrefDuties *aggStore[propPrefKey]

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery
	queryCallback  func([]readQuery) // Callback for testing.

	quit      chan struct{}
	deadliner core.Deadliner
}

// Store implements core.AggSigDB, see its godoc.
func (db *MemDB) Store(ctx context.Context, duty core.Duty, set core.SignedDataSet) error {
	for pubKey, data := range set {
		if err := db.store(ctx, duty, pubKey, data); err != nil {
			return err
		}
	}

	return nil
}

func (db *MemDB) store(ctx context.Context, duty core.Duty, pubKey core.PubKey, data core.SignedData) error {
	clone, err := data.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	response := make(chan error, 1)
	cmd := writeCommand{
		duty:     duty,
		pubKey:   pubKey,
		data:     clone,
		response: response,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-db.quit:
		return ErrStopped
	case db.commands <- cmd:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-db.quit:
		return ErrStopped
	case err := <-response:
		return err
	}
}

// Await implements core.AggSigDB, see its godoc.
func (db *MemDB) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey, subcommIdx core.SubcommitteeIndex) (core.SignedData, error) {
	if duty.Type == core.DutyProposerPreferences {
		return nil, errNotAwaitable
	}

	cancel := make(chan struct{})
	defer close(cancel)

	response := make(chan core.SignedData, 1)

	query := readQuery{
		duty:       duty,
		pubKey:     pubKey,
		subcommIdx: subcommIdx,
		response:   response,
		cancel:     cancel,
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-db.quit:
		return nil, ErrStopped
	case db.queries <- query:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-db.quit:
		return nil, ErrStopped
	case value := <-response:
		return value.Clone() // Clone before returning.
	}
}

// Run blocks and runs the database process until the context is cancelled.
func (db *MemDB) Run(ctx context.Context) {
	defer close(db.quit)

	for {
		select {
		case command := <-db.commands:
			db.execCommand(command)
			db.processBlockedQueries()
			db.callbackBlockedQueriesForT()
		case query := <-db.queries:
			if !db.execQuery(query) {
				db.blockedQueries = append(db.blockedQueries, query)
				db.callbackBlockedQueriesForT()
			}
		case duty := <-db.deadliner.C():
			db.generalDuties.trim(duty)
			db.subCommDuties.trim(duty)
			db.propPrefDuties.trim(duty)
		case <-ctx.Done():
			return
		}
	}
}

// execCommand executes a write command.
func (db *MemDB) execCommand(command writeCommand) {
	defer close(command.response)

	_ = db.deadliner.Add(command.duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	if err := db.storeRouted(command.duty, command.pubKey, command.data); err != nil {
		command.response <- err
	}
}

// execQuery returns true if the query was successfully executed.
// If the requested entry is found in the DB it will be returned via query.response channel.
func (db *MemDB) execQuery(query readQuery) bool {
	data, ok := db.get(query.duty, query.pubKey, query.subcommIdx)
	if !ok {
		return false
	}

	query.response <- data

	close(query.response)

	return true
}

// processBlockedQueries loops over the blockedQueries and executes them.
// For each of them that have an entry in the DB it will be returned via query.response channel
// and removed from blockedQueries.
func (db *MemDB) processBlockedQueries() {
	queries := db.blockedQueries
	db.blockedQueries = nil

	for _, query := range queries {
		if cancelled(query.cancel) {
			continue
		}

		if !db.execQuery(query) {
			db.blockedQueries = append(db.blockedQueries, query)
		}
	}
}

// callbackBlockedQueriesForT calls the queryCallback with the blocked queries for testing.
func (db *MemDB) callbackBlockedQueriesForT() {
	if db.queryCallback != nil {
		db.queryCallback(db.blockedQueries)
	}
}

// cancelled returns true if the channel is closed.
func cancelled(cancel <-chan struct{}) bool {
	select {
	case <-cancel:
		return true
	default:
		return false
	}
}

// writeCommand holds the data to write into the database.
type writeCommand struct {
	duty   core.Duty
	pubKey core.PubKey

	data     core.SignedData
	response chan<- error
}

// readQuery holds the query data and the response channel.
type readQuery struct {
	duty       core.Duty
	pubKey     core.PubKey
	subcommIdx core.SubcommitteeIndex

	response chan<- core.SignedData
	cancel   <-chan struct{}
}

// generalKey identifies aggregates for duties with a single message per duty and validator.
type generalKey struct {
	duty   core.Duty
	pubKey core.PubKey
}

// subCommKey additionally carries the sync subcommittee index for sync-committee aggregator
// duties (DutyPrepareSyncContribution, DutySyncContribution). A validator can occupy multiple
// sync subcommittees in the same slot, so it disambiguates their otherwise-colliding aggregates.
type subCommKey struct {
	duty       core.Duty
	pubKey     core.PubKey
	subcommIdx core.SubcommitteeIndex
}

// propPrefKey additionally carries the proposer preferences fields that may legitimately change
// for the same duty and pubkey: a reorg changes the dependent root, or operators change the fee
// recipient or gas limit in sync, and a new aggregate reaches threshold. It disambiguates the
// aggregates so each message is stored independently.
type propPrefKey struct {
	duty           core.Duty
	pubKey         core.PubKey
	dependentRoot  eth2p0.Root
	feeRecipient   bellatrix.ExecutionAddress
	targetGasLimit uint64
}

// propPrefKeyFor returns the propPrefKey for the provided proposer preferences aggregate.
func propPrefKeyFor(duty core.Duty, pubKey core.PubKey, data core.SignedData) (propPrefKey, error) {
	pref, ok := data.(core.SignedProposerPreferences)
	if !ok || pref.Message == nil {
		return propPrefKey{}, errors.New("invalid proposer preferences data")
	}

	return propPrefKey{
		duty:           duty,
		pubKey:         pubKey,
		dependentRoot:  pref.Message.DependentRoot,
		feeRecipient:   pref.Message.FeeRecipient,
		targetGasLimit: pref.Message.TargetGasLimit,
	}, nil
}

// storeRouted routes the aggregate to its duty family store. Callers must clone data
// before storing.
func (db *MemDB) storeRouted(duty core.Duty, pubKey core.PubKey, data core.SignedData) error {
	switch duty.Type {
	case core.DutyPrepareSyncContribution, core.DutySyncContribution:
		subcommIdx, err := core.SyncSubcommitteeIndex(duty.Type, data)
		if err != nil {
			return err
		}

		return db.subCommDuties.store(duty, subCommKey{duty: duty, pubKey: pubKey, subcommIdx: subcommIdx}, data)
	case core.DutyProposerPreferences:
		k, err := propPrefKeyFor(duty, pubKey, data)
		if err != nil {
			return err
		}

		return db.propPrefDuties.store(duty, k, data)
	default:
		return db.generalDuties.store(duty, generalKey{duty: duty, pubKey: pubKey}, data)
	}
}

// get returns the aggregate for the provided awaitable duty. Proposer preferences are not
// awaitable, Await rejects them before querying.
func (db *MemDB) get(duty core.Duty, pubKey core.PubKey, subcommIdx core.SubcommitteeIndex) (core.SignedData, bool) {
	switch duty.Type {
	case core.DutyPrepareSyncContribution, core.DutySyncContribution:
		return db.subCommDuties.get(subCommKey{duty: duty, pubKey: pubKey, subcommIdx: subcommIdx})
	default:
		return db.generalDuties.get(generalKey{duty: duty, pubKey: pubKey})
	}
}

// newAggStore returns a new empty aggregate store.
func newAggStore[K comparable]() *aggStore[K] {
	return &aggStore[K]{
		data:       make(map[K]core.SignedData),
		keysByDuty: make(map[core.Duty][]K),
	}
}

// aggStore holds aggregates for one duty family, keyed by the family's identity.
// It is not thread safe, synchronisation is up to the caller.
type aggStore[K comparable] struct {
	data       map[K]core.SignedData
	keysByDuty map[core.Duty][]K // Key index by duty for fast deletion.
}

// store stores the aggregate at the provided key. Storing an identical aggregate again is a
// no-op, storing a different aggregate at an existing key is an error.
func (s *aggStore[K]) store(duty core.Duty, k K, data core.SignedData) error {
	if existing, ok := s.data[k]; ok {
		equal, err := dataEqual(existing, data)
		if err != nil {
			return err
		} else if !equal {
			return errors.New("mismatching data")
		}

		return nil
	}

	s.data[k] = data
	s.keysByDuty[duty] = append(s.keysByDuty[duty], k)

	return nil
}

// get returns the aggregate stored at the provided key.
func (s *aggStore[K]) get(k K) (core.SignedData, bool) {
	data, ok := s.data[k]

	return data, ok
}

// trim deletes all aggregates for the provided duty. It writes nothing for unknown duties.
func (s *aggStore[K]) trim(duty core.Duty) {
	keys, ok := s.keysByDuty[duty]
	if !ok {
		return
	}

	for _, k := range keys {
		delete(s.data, k)
	}

	delete(s.keysByDuty, duty)
}

// dataEqual returns true if the provided signed data is equal.
func dataEqual(x core.SignedData, y core.SignedData) (bool, error) {
	bx, err := x.MarshalJSON()
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}

	by, err := y.MarshalJSON()
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}

	return bytes.Equal(bx, by), nil
}

// memDBKey identifies aggregates in the legacy MemDBV2 implementation.
// TODO(kalo): remove together with MemDBV2, it is unused by MemDB.
type memDBKey struct {
	duty   core.Duty
	pubKey core.PubKey
	// subcommIdx is the sync subcommittee index for sync-committee aggregator
	// duties (DutyPrepareSyncContribution, DutySyncContribution), and 0 otherwise.
	subcommIdx core.SubcommitteeIndex
}
