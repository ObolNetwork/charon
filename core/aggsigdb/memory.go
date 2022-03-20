// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggsigdb

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB() *MemDB {
	return &MemDB{
		data:           make(map[memDBKey]core.AggSignedData),
		commands:       make(chan writeCommand),
		queries:        make(chan readQuery),
		blockedQueries: []readQuery{},

		closingCh: make(chan struct{}),
		closedCh:  make(chan struct{}),
	}
}

// MemDB is a basic memory implementation of core.AggSigDB.
type MemDB struct {
	data map[memDBKey]core.AggSignedData

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery

	// required to stop gorutine
	runOnce        sync.Once
	closingCh      chan struct{}
	closedCh       chan struct{}
	writersWG      sync.WaitGroup
	writersWGMutex sync.Mutex
}

// Store implements core.AggSigDB, see its godoc.
func (db *MemDB) Store(ctx context.Context, duty core.Duty, pubKey core.PubKey, data core.AggSignedData) error {
	db.writersWGMutex.Lock()
	db.writersWG.Add(1)
	db.writersWGMutex.Unlock()
	defer db.writersWG.Done()

	select {
	case <-db.closingCh:
		return errors.New("database stopped")
	default:
	}

	response := make(chan error, 1)
	db.commands <- writeCommand{
		memDBKey: memDBKey{duty, pubKey},
		data:     data,
		response: response,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-response:
		return err
	}
}

// Await implements core.AggSigDB, see its godoc.
func (db *MemDB) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey) (core.AggSignedData, error) {
	db.writersWGMutex.Lock()
	db.writersWG.Add(1)
	db.writersWGMutex.Unlock()
	defer db.writersWG.Done()

	select {
	case <-db.closingCh:
		return core.AggSignedData{}, errors.New("database stopped")
	default:
	}

	response := make(chan core.AggSignedData, 1)
	query := readQuery{
		memDBKey: memDBKey{duty, pubKey},
		response: response,
	}

	db.queries <- query

	select {
	case <-ctx.Done():
		return core.AggSignedData{}, ctx.Err()
	case value := <-response:
		return value, nil
	}
}

// Run starts memDB processing goroutine.
func (db *MemDB) Run(ctx context.Context) {
	db.runOnce.Do(func() {
		go db.loop()

		go func() {
			<-ctx.Done()
			db.close()
		}()
	})
}

// loop over commands and queries to serialise them.
func (db *MemDB) loop() {
	for {
		select {
		case command, ok := <-db.commands:
			if !ok {
				return
			}
			db.execCommand(command)
			db.processBlockedQueries()
		case query, ok := <-db.queries:
			if !ok {
				return
			}
			if db.execQuery(query) {
				db.blockedQueries = append(db.blockedQueries, query)
			}
		case <-db.closedCh:
			return
		}
	}
}

// execCommand executes a write command.
func (db *MemDB) execCommand(command writeCommand) {
	key := memDBKey{command.duty, command.pubKey}

	curData, ok := db.data[key]
	if ok && !curData.Equal(command.data) {
		command.response <- errors.New("trying to update entry in aggsigdb/MemDB")
		close(command.response)

		return
	}

	if !ok {
		db.data[key] = command.data
	}

	command.response <- nil
	close(command.response)
}

// execQuery executes a read query, returns true if the query is blocked.
// If the requested entry is found in the DB it will return it via query.response channel,
// if it is not present it will store the query in blockedQueries.
func (db *MemDB) execQuery(query readQuery) bool {
	data, ok := db.data[memDBKey{query.duty, query.pubKey}]
	if ok {
		query.response <- data
		close(query.response)

		return false
	}

	return true
}

// processBlockedQueries loops over the blockedQueries and executes them.
// For each of them that have an entry in the DB it will be returned via query.response channel
// and removed from blockedQueries.
func (db *MemDB) processBlockedQueries() {
	queries := db.blockedQueries
	db.blockedQueries = []readQuery{}

	for _, query := range queries {
		if db.execQuery(query) {
			db.blockedQueries = append(db.blockedQueries, query)
		}
	}
}

func (db *MemDB) close() {
	close(db.closingCh)

	db.writersWGMutex.Lock()
	db.writersWG.Wait()
	db.writersWGMutex.Unlock()

	close(db.closedCh)
	close(db.commands)
	close(db.queries)
}

type memDBKey struct {
	duty   core.Duty
	pubKey core.PubKey
}

// writeCommand holds the data to write into the database.
type writeCommand struct {
	memDBKey
	data     core.AggSignedData
	response chan<- error
}

// readQuery holds the query data and the response channel.
type readQuery struct {
	memDBKey
	response chan<- core.AggSignedData
}
