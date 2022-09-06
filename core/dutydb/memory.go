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

package dutydb

import (
	"context"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// NewMemDB returns a new in-memory dutyDB instance.
func NewMemDB(deadliner core.Deadliner) *MemDB {
	return &MemDB{
		attDuties:         make(map[attKey]*eth2p0.AttestationData),
		attPubKeys:        make(map[pkKey]core.PubKey),
		attKeysBySlot:     make(map[int64][]pkKey),
		builderProDuties:  make(map[int64]*eth2api.VersionedBlindedBeaconBlock),
		proDuties:         make(map[int64]*spec.VersionedBeaconBlock),
		commResDuties:     make(map[commResKey]*eth2exp.BeaconCommitteeSubscriptionResponse),
		commResKeysBySlot: make(map[int64][]commResKey),
		shutdown:          make(chan struct{}),
		deadliner:         deadliner,
	}
}

// MemDB is a in-memory dutyDB implementation.
// It is a placeholder for the badgerDB implementation.
type MemDB struct {
	mu                sync.Mutex
	attDuties         map[attKey]*eth2p0.AttestationData
	attPubKeys        map[pkKey]core.PubKey
	attKeysBySlot     map[int64][]pkKey
	attQueries        []attQuery
	builderProDuties  map[int64]*eth2api.VersionedBlindedBeaconBlock
	builderProQueries []builderProQuery
	proDuties         map[int64]*spec.VersionedBeaconBlock
	proQueries        []proQuery
	commResDuties     map[commResKey]*eth2exp.BeaconCommitteeSubscriptionResponse
	commResQueries    []commResQuery
	commResKeysBySlot map[int64][]commResKey
	shutdown          chan struct{}
	deadliner         core.Deadliner
}

// Shutdown results in all blocking queries to return shutdown errors.
// Note this may once be called *once*.
func (db *MemDB) Shutdown() {
	close(db.shutdown)
}

// Store implements core.DutyDB, see its godoc.
func (db *MemDB) Store(_ context.Context, duty core.Duty, unsignedSet core.UnsignedDataSet) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.deadliner.Add(duty) {
		return errors.New("not storing unsigned data for expired duty", z.Any("duty", duty))
	}

	switch duty.Type {
	case core.DutyProposer:
		// Sanity check max one proposer per slot
		if len(unsignedSet) > 1 {
			return errors.New("unexpected proposer data set length", z.Int("n", len(unsignedSet)))
		}
		for _, unsignedData := range unsignedSet {
			err := db.storeBeaconBlockUnsafe(unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveProQueriesUnsafe()
	case core.DutyBuilderProposer:
		// Sanity check max one builder proposer per slot
		if len(unsignedSet) > 1 {
			return errors.New("unexpected builder proposer data set length", z.Int("n", len(unsignedSet)))
		}
		for _, unsignedData := range unsignedSet {
			err := db.storeBlindedBeaconBlockUnsafe(unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveBuilderProQueriesUnsafe()
	case core.DutyAttester:
		for pubkey, unsignedData := range unsignedSet {
			err := db.storeAttestationUnsafe(pubkey, unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveAttQueriesUnsafe()
	case core.DutyPrepareAggregator:
		for _, unsignedData := range unsignedSet {
			err := db.storeBeaconCommitteeSubscriptionResponseUnsafe(duty.Slot, unsignedData)
			if err != nil {
				return err
			}
		}
		db.resolveCommResQueriesUnsafe()
	default:
		return errors.New("unsupported duty type", z.Str("type", duty.Type.String()))
	}

	// Delete all expired duties.
	for {
		var deleted bool
		select {
		case duty := <-db.deadliner.C():
			err := db.deleteDutyUnsafe(duty)
			if err != nil {
				return err
			}
			deleted = true
		default:
		}

		if !deleted {
			break
		}
	}

	return nil
}

// AwaitBeaconBlock implements core.DutyDB, see its godoc.
func (db *MemDB) AwaitBeaconBlock(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error) {
	db.mu.Lock()
	response := make(chan *spec.VersionedBeaconBlock, 1)
	db.proQueries = append(db.proQueries, proQuery{
		Key:      slot,
		Response: response,
	})
	db.resolveProQueriesUnsafe()
	db.mu.Unlock()

	select {
	case <-db.shutdown:
		return nil, errors.New("dutydb shutdown")
	case <-ctx.Done():
		return nil, ctx.Err()
	case block := <-response:
		return block, nil
	}
}

// AwaitBlindedBeaconBlock implements core.DutyDB, see its godoc.
func (db *MemDB) AwaitBlindedBeaconBlock(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error) {
	db.mu.Lock()
	response := make(chan *eth2api.VersionedBlindedBeaconBlock, 1)
	db.builderProQueries = append(db.builderProQueries, builderProQuery{
		Key:      slot,
		Response: response,
	})
	db.resolveBuilderProQueriesUnsafe()
	db.mu.Unlock()

	select {
	case <-db.shutdown:
		return nil, errors.New("dutydb shutdown")
	case <-ctx.Done():
		return nil, ctx.Err()
	case block := <-response:
		return block, nil
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
	case <-db.shutdown:
		return nil, errors.New("dutydb shutdown")
	case <-ctx.Done():
		return nil, ctx.Err()
	case value := <-response:
		return value, nil
	}
}

// AwaitCommitteeSubscriptionResponse implements core.DutyDB, see its godoc.
func (db *MemDB) AwaitCommitteeSubscriptionResponse(ctx context.Context, slot int64, vIdx int64) (*eth2exp.BeaconCommitteeSubscriptionResponse, error) {
	db.mu.Lock()
	response := make(chan *eth2exp.BeaconCommitteeSubscriptionResponse, 1) // Buffer of one so resolving never blocks
	db.commResQueries = append(db.commResQueries, commResQuery{
		Key: commResKey{
			Slot: slot,
			Vidx: vIdx,
		},
		Response: response,
	})
	db.resolveCommResQueriesUnsafe()
	db.mu.Unlock()

	select {
	case <-db.shutdown:
		return nil, errors.New("dutydb shutdown")
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
	cloned, err := unsignedData.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	attData, ok := cloned.(core.AttestationData)
	if !ok {
		return errors.New("invalid unsigned attestation data")
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
		db.attKeysBySlot[int64(attData.Duty.Slot)] = append(db.attKeysBySlot[int64(attData.Duty.Slot)], pKey)
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
func (db *MemDB) storeBeaconBlockUnsafe(unsignedData core.UnsignedData) error {
	cloned, err := unsignedData.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	block, ok := cloned.(core.VersionedBeaconBlock)
	if !ok {
		return errors.New("invalid unsigned block")
	}

	slot, err := block.Slot()
	if err != nil {
		return err
	}

	if existing, ok := db.proDuties[int64(slot)]; ok {
		existingRoot, err := existing.Root()
		if err != nil {
			return errors.Wrap(err, "block root")
		}

		providedRoot, err := block.Root()
		if err != nil {
			return errors.Wrap(err, "block root")
		}

		if existingRoot != providedRoot {
			return errors.New("clashing blocks")
		}
	} else {
		db.proDuties[int64(slot)] = &block.VersionedBeaconBlock
	}

	return nil
}

// storeBlindedBeaconBlockUnsafe stores the unsigned BlindedBeaconBlock. It is unsafe since it assumes the lock is held.
func (db *MemDB) storeBlindedBeaconBlockUnsafe(unsignedData core.UnsignedData) error {
	cloned, err := unsignedData.Clone() // Clone before storing.
	if err != nil {
		return err
	}

	block, ok := cloned.(core.VersionedBlindedBeaconBlock)
	if !ok {
		return errors.New("invalid unsigned blinded block")
	}

	slot, err := block.Slot()
	if err != nil {
		return err
	}

	if existing, ok := db.builderProDuties[int64(slot)]; ok {
		existingRoot, err := existing.Root()
		if err != nil {
			return errors.Wrap(err, "blinded block root")
		}

		providedRoot, err := block.Root()
		if err != nil {
			return errors.Wrap(err, "blinded block root")
		}

		if existingRoot != providedRoot {
			return errors.New("clashing blinded blocks")
		}
	} else {
		db.builderProDuties[int64(slot)] = &block.VersionedBlindedBeaconBlock
	}

	return nil
}

// storeBeaconCommitteeSubscriptionResponseUnsafe stores BeaconCommitteeSubscriptionResponse.
// It is unsafe since it assumes the lock is held.
func (db *MemDB) storeBeaconCommitteeSubscriptionResponseUnsafe(slot int64, unsignedData core.UnsignedData) error {
	cloned, err := unsignedData.Clone()
	if err != nil {
		return err
	}

	res, ok := cloned.(core.BeaconCommitteeSubscriptionResponse)
	if !ok {
		return errors.New("invalid committee subscription response")
	}

	key := commResKey{
		Slot: slot,
		Vidx: int64(res.ValidatorIndex),
	}

	if existing, ok := db.commResDuties[key]; ok {
		if existing.IsAggregator != res.IsAggregator {
			return errors.New("clashing committee subscription response", z.Any("key", key))
		}
	} else {
		db.commResDuties[key] = &res.BeaconCommitteeSubscriptionResponse
		db.commResKeysBySlot[slot] = append(db.commResKeysBySlot[slot], key)
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

// resolveBuilderProQueriesUnsafe resolve any builderProQuery to a result if found.
// It is unsafe since it assume that the lock is held.
func (db *MemDB) resolveBuilderProQueriesUnsafe() {
	var unresolved []builderProQuery
	for _, query := range db.builderProQueries {
		value, ok := db.builderProDuties[query.Key]
		if !ok {
			unresolved = append(unresolved, query)
			continue
		}

		query.Response <- value
	}

	db.builderProQueries = unresolved
}

// resolveCommResQueriesUnsafe resolve any commResQuery to a result if found.
// It is unsafe since it assume that the lock is held.
func (db *MemDB) resolveCommResQueriesUnsafe() {
	var unresolved []commResQuery
	for _, query := range db.commResQueries {
		value, ok := db.commResDuties[query.Key]
		if !ok {
			unresolved = append(unresolved, query)
			continue
		}

		query.Response <- value
	}

	db.commResQueries = unresolved
}

// deleteDutyUnsafe deletes the duty from the database. It is unsafe since it assumes the lock is held.
func (db *MemDB) deleteDutyUnsafe(duty core.Duty) error {
	switch duty.Type {
	case core.DutyProposer:
		delete(db.proDuties, duty.Slot)
	case core.DutyBuilderProposer:
		delete(db.builderProDuties, duty.Slot)
	case core.DutyAttester:
		for _, key := range db.attKeysBySlot[duty.Slot] {
			delete(db.attPubKeys, key)
			delete(db.attDuties, attKey{Slot: key.Slot, CommIdx: key.CommIdx})
		}
		delete(db.attKeysBySlot, duty.Slot)
	case core.DutyPrepareAggregator:
		for _, key := range db.commResKeysBySlot[duty.Slot] {
			delete(db.commResDuties, key)
		}
		delete(db.commResKeysBySlot, duty.Slot)
	default:
		return errors.New("unknown duty type")
	}

	return nil
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

// commResKey is the key to lookup committee subnet response in the DB.
type commResKey struct {
	Slot int64
	Vidx int64
}

// attQuery is a waiting attQuery with a response channel.
type attQuery struct {
	Key      attKey
	Response chan<- *eth2p0.AttestationData
}

// proQuery is a waiting proQuery with a response channel.
type proQuery struct {
	Key      int64
	Response chan<- *spec.VersionedBeaconBlock
}

// builderProQuery is a waiting builderProQuery with a response channel.
type builderProQuery struct {
	Key      int64
	Response chan<- *eth2api.VersionedBlindedBeaconBlock
}

// commResQuery is a waiting commResQuery with a response channel.
type commResQuery struct {
	Key      commResKey
	Response chan<- *eth2exp.BeaconCommitteeSubscriptionResponse
}
