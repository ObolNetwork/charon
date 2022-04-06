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

package dutydb

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// NewMemDB returns a new in-memory dutyDB instance.
func NewMemDB() *MemDB {
	return &MemDB{
		attDuties:  make(map[attKey]*eth2p0.AttestationData),
		attPubKeys: make(map[pkKey]core.PubKey),
		proDuties:  make(map[int64]*proValue),
	}
}

// MemDB is a in-memory dutyDB implementation.
// It is a placeholder for the badgerDB implementation.
type MemDB struct {
	mu         sync.Mutex
	attDuties  map[attKey]*eth2p0.AttestationData
	attPubKeys map[pkKey]core.PubKey
	attQueries []attQuery
	proDuties  map[int64]*proValue
	proQueries []proQuery
}

// Store implements core.DutyDB, see its godoc.
func (db *MemDB) Store(_ context.Context, duty core.Duty, unsignedSet core.UnsignedDataSet) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	switch duty.Type {
	case core.DutyProposer:
		for pubkey, unsignedData := range unsignedSet {
			err := db.storeBeaconBlockUnsafe(pubkey, unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveProQueriesUnsafe()
	case core.DutyAttester:
		for pubkey, unsignedData := range unsignedSet {
			err := db.storeAttestationUnsafe(pubkey, unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveAttQueriesUnsafe()
	default:
		return errors.New("unsupported duty type", z.Str("type", duty.Type.String()))
	}

	return nil
}

// AwaitBeaconBlock implements core.DutyDB, see its godoc.
func (db *MemDB) AwaitBeaconBlock(ctx context.Context, slot int64) (core.PubKey, *spec.VersionedBeaconBlock, error) {
	db.mu.Lock()
	response := make(chan *proValue, 1)
	db.proQueries = append(db.proQueries, proQuery{
		Key:      slot,
		Response: response,
	})
	db.resolveProQueriesUnsafe()
	db.mu.Unlock()

	select {
	case <-ctx.Done():
		return "", nil, ctx.Err()
	case value := <-response:
		return value.PubKey, value.Block, nil
	}
}

// AwaitAttestation implements core.DutyDB, see its godoc.
func (db *MemDB) AwaitAttestation(ctx context.Context, slot int64, commIdx int64) (*eth2p0.AttestationData, error) {
	db.mu.Lock()
	response := make(chan *eth2p0.AttestationData, 1) // Buffer of one so resolving never blocks
	db.attQueries = append(db.attQueries, attQuery{
		Key: attKey{
			Slot:    slot,
			CommIdx: commIdx,
		},
		Response: response,
	})
	db.resolveAttQueriesUnsafe()
	db.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case value := <-response:
		return value, nil
	}
}

// PubKeyByAttestation implements core.DutyDB, see its godoc.
func (db *MemDB) PubKeyByAttestation(_ context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := pkKey{
		Slot:       slot,
		CommIdx:    commIdx,
		ValCommIdx: valCommIdx,
	}

	pubkey, ok := db.attPubKeys[key]
	if !ok {
		return "", errors.New("pubkey not found")
	}

	return pubkey, nil
}

// storeAttestationUnsafe stores the unsigned attestation. It is unsafe since it assumes the lock is held.
func (db *MemDB) storeAttestationUnsafe(pubkey core.PubKey, unsignedData core.UnsignedData) error {
	attData, err := core.DecodeAttesterUnsignedData(unsignedData)
	if err != nil {
		return err
	}

	// Store key and value for PubKeyByAttestation
	pKey := pkKey{
		Slot:       int64(attData.Data.Slot),
		CommIdx:    int64(attData.Data.Index),
		ValCommIdx: int64(attData.Duty.ValidatorCommitteeIndex),
	}
	if value, ok := db.attPubKeys[pKey]; ok {
		if value != pubkey {
			return errors.New("clashing public key", z.Any("key", pKey))
		}
	} else {
		db.attPubKeys[pKey] = pubkey
	}

	// Store key and value for AwaitAttestation
	aKey := attKey{
		Slot:    int64(attData.Data.Slot),
		CommIdx: int64(attData.Data.Index),
	}

	if value, ok := db.attDuties[aKey]; ok {
		if value.String() != attData.Data.String() {
			return errors.New("clashing attestation data", z.Any("key", aKey))
		}
	} else {
		db.attDuties[aKey] = &attData.Data
	}

	return nil
}

// storeBeaconBlockUnsafe stores the unsigned BeaconBlock. It is unsafe since it assumes the lock is held.
func (db *MemDB) storeBeaconBlockUnsafe(pubkey core.PubKey, unsignedData core.UnsignedData) error {
	block, err := core.DecodeProposerUnsignedData(unsignedData)
	if err != nil {
		return err
	}

	slot, err := block.Slot()
	if err != nil {
		return err
	}

	data := proValue{
		PubKey: pubkey,
		Block:  block,
	}

	if value, ok := db.proDuties[int64(slot)]; ok {
		if value.PubKey != pubkey {
			return errors.New("clashing block proposer")
		}

		b, err := json.Marshal(value.Block)
		if err != nil {
			return errors.Wrap(err, "marshalling block")
		}

		if !bytes.Equal(b, unsignedData) {
			return errors.New("clashing blocks")
		}
	} else {
		db.proDuties[int64(slot)] = &data
	}

	return nil
}

// resolveAttQueriesUnsafe resolve any attQuery to a result if found.
// It is unsafe since it assume that the lock is held.
func (db *MemDB) resolveAttQueriesUnsafe() {
	var unresolved []attQuery
	for _, query := range db.attQueries {
		value, ok := db.attDuties[query.Key]
		if !ok {
			unresolved = append(unresolved, query)
			continue
		}

		query.Response <- value
	}

	db.attQueries = unresolved
}

// resolveProQueriesUnsafe resolve any proQuery to a result if found.
// It is unsafe since it assume that the lock is held.
func (db *MemDB) resolveProQueriesUnsafe() {
	var unresolved []proQuery
	for _, query := range db.proQueries {
		value, ok := db.proDuties[query.Key]
		if !ok {
			unresolved = append(unresolved, query)
			continue
		}

		query.Response <- value
	}

	db.proQueries = unresolved
}

// attKey is the key to lookup an attester value in the DB.
type attKey struct {
	Slot    int64
	CommIdx int64
}

// pkKey is the key to lookup pubkeys by attestation in the DB.
type pkKey struct {
	Slot       int64
	CommIdx    int64
	ValCommIdx int64
}

// attQuery is a waiting attQuery with a response channel.
type attQuery struct {
	Key      attKey
	Response chan<- *eth2p0.AttestationData
}

// proQuery is a waiting proQuery with a response channel.
type proQuery struct {
	Key      int64
	Response chan<- *proValue
}

// proValue is a propser duty value with Public key and Beacon Block.
type proValue struct {
	PubKey core.PubKey
	Block  *spec.VersionedBeaconBlock
}
