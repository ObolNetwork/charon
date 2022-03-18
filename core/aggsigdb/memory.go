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
	"fmt"

	"github.com/obolnetwork/charon/core"
)

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB() core.AggSigDB {
	db := &memDB{
		data:           make(map[string]core.AggSignedData),
		commands:       make(chan writeCommand),
		queries:        make(chan readQuery),
		blockedQueries: []readQuery{},
	}

	go db.loop()

	return db
}

// Store implements core.AggSigDB, see its godoc.
func (db *memDB) Store(_ context.Context, duty core.Duty, pubKey core.PubKey, data core.AggSignedData) error {
	db.commands <- writeCommand{
		duty:   duty,
		pubKey: pubKey,
		data:   data,
	}

	return nil
}

// Await implements core.AggSigDB, see its godoc.
func (db *memDB) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey) (core.AggSignedData, error) {
	response := make(chan core.AggSignedData)
	query := readQuery{
		duty:     duty,
		pubKey:   pubKey,
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

// memDB is a basic memory implementation of core.AggSigDB.
type memDB struct {
	data map[string]core.AggSignedData

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery
}

// loop over commands and queries to serialise them.
func (db *memDB) loop() {
	for {
		select {
		case command := <-db.commands:
			db.execCommand(command)
			db.processBlockedQueries()
		case query := <-db.queries:
			db.execQuery(query)
		}
	}
}

// execCommand executes a write command.
func (db *memDB) execCommand(command writeCommand) {
	db.data[db.getKey(command.duty, command.pubKey)] = command.data
}

// execQuery executes a read query.
// If the requested entry is found in the DB it will return it via query.response channel,
// if it is not present it will store the query in blockedQueries.
func (db *memDB) execQuery(query readQuery) {
	data, ok := db.data[db.getKey(query.duty, query.pubKey)]
	if ok {
		query.response <- data
		close(query.response)

		return
	}

	db.blockedQueries = append(db.blockedQueries, query)
}

// processBlockedQueries loops over the blockedQueries and executes them.
// For each of them that have an entry in the DB it will be returned via query.response channel
// and removed from blockedQueries.
func (db *memDB) processBlockedQueries() {
	queries := db.blockedQueries
	db.blockedQueries = []readQuery{}

	for _, query := range queries {
		db.execQuery(query)
	}
}

// getKey returns the key used to map a database entry.
func (memDB) getKey(duty core.Duty, pubKey core.PubKey) string {
	return fmt.Sprintf("/%d", duty.Slot) + "/" + duty.Type.String() + "/" + pubKey.String()
}

// writeCommand holds the data to write into the database.
type writeCommand struct {
	duty   core.Duty
	pubKey core.PubKey
	data   core.AggSignedData
}

// readQuery holds the query data and the response channel.
type readQuery struct {
	duty     core.Duty
	pubKey   core.PubKey
	response chan<- core.AggSignedData
}
