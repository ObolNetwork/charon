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

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB() core.AggSigDB {
	db := &memDB{
		data:           make(map[memDBKey]core.AggSignedData),
		commands:       make(chan writeCommand),
		queries:        make(chan readQuery),
		blockedQueries: []readQuery{},
	}

	go db.loop()

	return db
}

// memDB is a basic memory implementation of core.AggSigDB.
type memDB struct {
	data map[memDBKey]core.AggSignedData

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery
}

// Store implements core.AggSigDB, see its godoc.
func (db *memDB) Store(ctx context.Context, duty core.Duty, pubKey core.PubKey, data core.AggSignedData) error {
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
func (db *memDB) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey) (core.AggSignedData, error) {
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

// loop over commands and queries to serialise them.
func (db *memDB) loop() {
	for {
		select {
		case command := <-db.commands:
			db.execCommand(command)
			db.processBlockedQueries()
		case query := <-db.queries:
			if db.execQuery(query) {
				db.blockedQueries = append(db.blockedQueries, query)
			}
		}
	}
}

// execCommand executes a write command.
func (db *memDB) execCommand(command writeCommand) {
	key := memDBKey{command.duty, command.pubKey}

	curData, ok := db.data[key]
	if ok && !curData.Equal(command.data) {
		command.response <- errors.New("trying to update entry in aggsigdb/memDB")
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
func (db *memDB) execQuery(query readQuery) bool {
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
func (db *memDB) processBlockedQueries() {
	queries := db.blockedQueries
	db.blockedQueries = []readQuery{}

	for _, query := range queries {
		if db.execQuery(query) {
			db.blockedQueries = append(db.blockedQueries, query)
		}
	}
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
