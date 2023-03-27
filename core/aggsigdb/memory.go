// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb

import (
	"bytes"
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

type dataMap struct {
	sync.Map
	count uint64
}

func (dm *dataMap) get(key memDBKey) (core.SignedData, bool) {
	rawData, ok := dm.Load(key)
	if !ok {
		return nil, false
	}

	sd, canCast := rawData.(core.SignedData)
	if !canCast {
		return nil, false
	}

	return sd, true
}

func (dm *dataMap) set(key memDBKey, value core.SignedData) {
	dm.Store(key, value)
	dm.count++
}

func (dm *dataMap) delete(key memDBKey) {
	dm.Delete(key)
	if dm.count != 0 {
		dm.count--
	}
}

type keysByDutyMap struct {
	sync.Map
	count uint64
}

//nolint:unparam
func (kdb *keysByDutyMap) get(key core.Duty) ([]memDBKey, bool) {
	rawData, ok := kdb.Load(key)
	if !ok {
		return nil, false
	}

	sd, canCast := rawData.([]memDBKey)
	if !canCast {
		return nil, false
	}

	return sd, true
}

func (kdb *keysByDutyMap) set(key core.Duty, value []memDBKey) {
	kdb.Store(key, value)
	kdb.count++
}

func (kdb *keysByDutyMap) delete(key core.Duty) {
	kdb.Delete(key)
	if kdb.count != 0 {
		kdb.count--
	}
}

var ErrStopped = errors.New("database stopped")

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB(deadliner core.Deadliner) *MemDB {
	return &MemDB{
		data:           dataMap{},
		keysByDuty:     keysByDutyMap{},
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
	data       dataMap
	keysByDuty keysByDutyMap // Key index by duty for fast deletion.

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery
	queryCallback  func([]readQuery) // Callback for testing.

	quit      chan struct{}
	deadliner core.Deadliner
}

// Store implements core.AggSigDB, see its godoc.
func (db *MemDB) Store(ctx context.Context, duty core.Duty, pubKey core.PubKey, data core.SignedData) error {
	clone, err := data.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	response := make(chan error, 1)
	cmd := writeCommand{
		memDBKey: memDBKey{duty, pubKey},
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
func (db *MemDB) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey) (core.SignedData, error) {
	cancel := make(chan struct{})
	defer close(cancel)
	response := make(chan core.SignedData, 1)

	query := readQuery{
		memDBKey: memDBKey{duty, pubKey},
		response: response,
		cancel:   cancel,
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
			kbd, _ := db.keysByDuty.get(duty)
			for _, key := range kbd {
				db.data.delete(key)
			}
			db.keysByDuty.delete(duty)
		case <-ctx.Done():
			return
		}
	}
}

// execCommand executes a write command.
func (db *MemDB) execCommand(command writeCommand) {
	defer close(command.response)

	_ = db.deadliner.Add(command.duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	key := memDBKey{command.duty, command.pubKey}

	if existing, ok := db.data.get(key); ok {
		equal, err := dataEqual(existing, command.data)
		if err != nil {
			command.response <- err
		} else if !equal {
			command.response <- errors.New("mismatching data")
		}
	} else {
		db.data.set(key, command.data)

		old, _ := db.keysByDuty.get(command.duty)
		old = append(old, key)
		db.keysByDuty.set(command.duty, old)
	}
}

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

// execQuery returns true if the query was successfully executed.
// If the requested entry is found in the DB it will return it via query.response channel.
func (db *MemDB) execQuery(query readQuery) bool {
	data, ok := db.data.get(memDBKey{query.duty, query.pubKey})
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

type memDBKey struct {
	duty   core.Duty
	pubKey core.PubKey
}

// writeCommand holds the data to write into the database.
type writeCommand struct {
	memDBKey
	data     core.SignedData
	response chan<- error
}

// readQuery holds the query data and the response channel.
type readQuery struct {
	memDBKey
	response chan<- core.SignedData
	cancel   <-chan struct{}
}
