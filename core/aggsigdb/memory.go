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

package aggsigdb

import (
	"bytes"
	"context"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

var ErrStopped = errors.New("database stopped")

// NewMemDB creates a basic memory based AggSigDB.
func NewMemDB() *MemDB {
	return &MemDB{
		data:           make(map[memDBKey]core.SignedData),
		commands:       make(chan writeCommand),
		queries:        make(chan readQuery),
		blockedQueries: []readQuery{},
		quit:           make(chan struct{}),
	}
}

// MemDB is a basic memory implementation of core.AggSigDB.
type MemDB struct {
	data map[memDBKey]core.SignedData

	commands       chan writeCommand
	queries        chan readQuery
	blockedQueries []readQuery

	quit chan struct{}
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
	response := make(chan core.SignedData, 1)
	query := readQuery{
		memDBKey: memDBKey{duty, pubKey},
		response: response,
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
		case query := <-db.queries:
			if !db.execQuery(query) {
				db.blockedQueries = append(db.blockedQueries, query)
			}
		case <-ctx.Done():
			return
		}
	}
}

// execCommand executes a write command.
func (db *MemDB) execCommand(command writeCommand) {
	key := memDBKey{command.duty, command.pubKey}

	if existing, ok := db.data[key]; ok {
		equal, err := dataEqual(existing, command.data)
		if err != nil {
			command.response <- err
		} else if !equal {
			command.response <- errors.New("mismatching data")
		}
	} else {
		db.data[key] = command.data
	}

	close(command.response)
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
	data, ok := db.data[memDBKey{query.duty, query.pubKey}]
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
		if !db.execQuery(query) {
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
	data     core.SignedData
	response chan<- error
}

// readQuery holds the query data and the response channel.
type readQuery struct {
	memDBKey
	response chan<- core.SignedData
}
