// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// maxExemptEntriesPerShare bounds how many distinct exempt-duty entries (e.g. exit epochs or
// builder registrations) are retained per (share index, validator, duty type). Exempt duties are
// never trimmed by the deadliner, so without a cap a single peer could store an unbounded number of
// them (e.g. by replaying a valid exit signature across arbitrary slots). A DV cluster only ever
// produces one such entry per validator per share, so 10 gives generous head-room for operator
// error while keeping memory bounded (N shares * 10 per validator per type).
const maxExemptEntriesPerShare = 10

// NewMemDBMetadata returns a new in-memory partial signature database instance.
func NewMemDBMetadata(slotDuration uint64, genesisTime time.Time) MemDBMetadata {
	return MemDBMetadata{
		slotDuration: slotDuration,
		genesisTime:  genesisTime,
	}
}

type MemDBMetadata struct {
	slotDuration uint64
	genesisTime  time.Time
}

// NewMemDB returns a new in-memory partial signature database instance.
func NewMemDB(threshold int, deadliner core.Deadliner, metadata MemDBMetadata) *MemDB {
	return &MemDB{
		entries:       make(map[key][]core.ParSignedData),
		keysByDuty:    make(map[core.Duty][]key),
		exemptEntries: make(map[exemptEntryKey][]key),
		threshold:     threshold,
		deadliner:     deadliner,
		metadata:      metadata,
	}
}

// MemDB is an in-memory partial signature database.
type MemDB struct {
	mu           sync.Mutex
	internalSubs []func(context.Context, core.Duty, core.ParSignedDataSet) error
	threshSubs   []func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error

	entries    map[key][]core.ParSignedData
	keysByDuty map[core.Duty][]key
	// exemptEntries indexes exempt-duty entries (which the deadliner never trims) by
	// (share index, validator, duty type) in insertion order, so they can be capped and
	// evicted oldest-first to bound memory.
	exemptEntries map[exemptEntryKey][]key
	threshold     int
	deadliner     core.Deadliner

	metadata MemDBMetadata
}

// SubscribeInternal registers a callback when an internal
// partially signed duty set is stored.
func (db *MemDB) SubscribeInternal(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.internalSubs = append(db.internalSubs, fn)
}

// SubscribeThreshold registers a callback when *threshold*
// partially signed duty is reached for a DV.
func (db *MemDB) SubscribeThreshold(fn func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.threshSubs = append(db.threshSubs, fn)
}

// StoreInternal stores an internally received partially signed duty data set.
func (db *MemDB) StoreInternal(ctx context.Context, duty core.Duty, signedSet core.ParSignedDataSet) error {
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	if err := db.StoreExternal(ctx, duty, signedSet); err != nil {
		return err
	}

	// Call internalSubs (which includes ParSigEx to exchange partial signed data with all peers).
	for _, sub := range db.internalSubs {
		clone, err := signedSet.Clone() // Clone before calling each subscriber.
		if err != nil {
			return err
		}

		if err = sub(ctx, duty, clone); err != nil {
			return err
		}
	}

	return nil
}

// StoreExternal stores an externally received partially signed duty data set.
func (db *MemDB) StoreExternal(ctx context.Context, duty core.Duty, signedSet core.ParSignedDataSet) error {
	// The deadliner drives all trimming: entries are only ever deleted when their duty is emitted on deadliner.C().
	// A duty whose deadline has already passed is never scheduled, so storing it would leak forever.
	// Duties that never expire must still be stored.
	status := db.deadliner.Add(duty)
	if status == core.DeadlineExpired {
		var shareIdx int
		for _, sig := range signedSet {
			shareIdx = sig.ShareIdx
			break
		}

		log.Warn(ctx, "Dropping partial signatures received for expired duty", nil,
			z.Any("duty", duty), z.Int("share_idx", shareIdx))

		return nil
	}

	// Exempt duties (exits, builder registrations) are never trimmed by the deadliner, so their
	// entries are capped per (share index, validator, duty type) in store to bound memory.
	exempt := status == core.DeadlineExempt

	output := make(map[core.PubKey][]core.ParSignedData)

	for pubkey, sig := range signedSet {
		sigs, ok, err := db.store(ctx, key{Duty: duty, PubKey: pubkey}, sig, exempt)
		if err != nil {
			return err
		} else if !ok {
			log.Debug(ctx, "Ignoring duplicate partial signature")

			continue
		}

		// Check if sufficient matching partial signed data has been received.
		psigs, ok, err := getThresholdMatching(duty.Type, sigs, db.threshold)
		if err != nil {
			return err
		} else if !ok {
			continue
		}

		output[pubkey] = psigs
	}

	if len(output) == 0 {
		return nil
	}

	// Call the threshSubs (which includes SigAgg component)
	for _, sub := range db.threshSubs {
		// Clone before calling each subscriber.
		if err := sub(ctx, duty, clone(output)); err != nil {
			return err
		}
	}

	return nil
}

// Trim blocks until the context is closed, it deletes state for expired duties.
// It should only be called once.
func (db *MemDB) Trim(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case duty := <-db.deadliner.C(): // This buffered channel is small, so we need dedicated goroutine to service it.
			db.mu.Lock()

			for _, key := range db.keysByDuty[duty] {
				delete(db.entries, key)
			}

			delete(db.keysByDuty, duty)
			db.mu.Unlock()
		}
	}
}

// store returns true if the value was added to the list of signatures at the provided key
// and returns a copy of the resulting list.
func (db *MemDB) store(ctx context.Context, k key, value core.ParSignedData, exempt bool) ([]core.ParSignedData, bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UnixMilli()

	slotStart := (uint64(db.metadata.genesisTime.Unix()) + k.Duty.Slot*db.metadata.slotDuration) * 1000 // in ms
	timeSinceSlotStart := float64(now-int64(slotStart)) / 1000                                          // in seconds

	switch k.Duty.Type {
	case core.DutyAttester:
		timeSinceSlotStart -= 4.0
	case core.DutyAggregator, core.DutySyncContribution:
		timeSinceSlotStart -= 8.0
	default:
	}

	// Observe time since slot start for received partial signatures, with share index as label for better visibility of late partial signatures.
	// Subtracting 1 from share index to have 0-based index.
	parsigStored.WithLabelValues(k.Duty.Type.String(), strconv.FormatInt(int64(value.ShareIdx-1), 10)).Observe(timeSinceSlotStart)

	for _, s := range db.entries[k] {
		if s.ShareIdx == value.ShareIdx {
			equal, err := parSignedDataEqual(s, value)
			if err != nil {
				return nil, false, err
			} else if !equal {
				return nil, false, errors.New("mismatching partial signed data",
					z.Any("pubkey", k.PubKey), z.Int("share_idx", s.ShareIdx))
			}

			return nil, false, nil
		}
	}

	// Clone before storing.
	clone, err := value.Clone()
	if err != nil {
		return nil, false, err
	}

	db.entries[k] = append(db.entries[k], clone)

	if exempt {
		// Exempt duties are never emitted on deadliner.C(), so they are tracked and capped
		// here (under the same lock) instead of being trimmed via keysByDuty.
		db.trackExemptUnsafe(ctx, k, value.ShareIdx)
	} else {
		db.keysByDuty[k.Duty] = append(db.keysByDuty[k.Duty], k)
	}

	if k.Duty.Type == core.DutyExit {
		exitCounter.WithLabelValues(k.PubKey.String()).Inc()
	}

	return append([]core.ParSignedData(nil), db.entries[k]...), true, nil
}

// clone returns a deep copy of the provided map.
func clone(output map[core.PubKey][]core.ParSignedData) map[core.PubKey][]core.ParSignedData {
	clone := make(map[core.PubKey][]core.ParSignedData)

	for pubkey, sigs := range output {
		var clones []core.ParSignedData

		for _, sig := range sigs {
			clone, err := sig.Clone()
			if err != nil {
				panic(err)
			}

			clones = append(clones, clone)
		}

		clone[pubkey] = clones
	}

	return clone
}

// getThresholdMatching returns true and threshold number of partial signed data with identical data or false.
func getThresholdMatching(typ core.DutyType, sigs []core.ParSignedData, threshold int) ([]core.ParSignedData, bool, error) {
	if len(sigs) < threshold {
		return nil, false, nil
	}

	if typ == core.DutySignature {
		// Signatures do not support message roots.
		return sigs, len(sigs) == threshold, nil
	}

	sigsByMsgRoot := make(map[[32]byte][]core.ParSignedData) // map[Root][]ParSignedData

	for _, sig := range sigs {
		root, err := sig.MessageRoot()
		if err != nil {
			return nil, false, err
		}

		sigsByMsgRoot[root] = append(sigsByMsgRoot[root], sig)
	}

	// Return true if we have "threshold" number of signatures.
	for _, set := range sigsByMsgRoot {
		if len(set) == threshold {
			return set, true, nil
		}
	}

	return nil, false, nil
}

func parSignedDataEqual(x, y core.ParSignedData) (bool, error) {
	xjson, err := json.Marshal(x)
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}

	yjson, err := json.Marshal(y)
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}

	return bytes.Equal(xjson, yjson), nil
}

type key struct {
	Duty   core.Duty
	PubKey core.PubKey
}

// exemptEntryKey indexes exempt-duty entries by share index, validator and duty type.
// Distinct entries within this key correspond to distinct duties (e.g. exit epochs).
type exemptEntryKey struct {
	ShareIdx int
	PubKey   core.PubKey
	DutyType core.DutyType
}

// trackExemptUnsafe records a newly stored exempt-duty entry for capping. It assumes db.mu is held
// and that k was just added as a new entry for shareIdx.
func (db *MemDB) trackExemptUnsafe(ctx context.Context, k key, shareIdx int) {
	ek := exemptEntryKey{ShareIdx: shareIdx, PubKey: k.PubKey, DutyType: k.Duty.Type}

	stored := db.exemptEntries[ek]
	if len(stored) > 0 {
		log.Warn(ctx, "Received exempt duty for validator with a different epoch/slot than already stored", nil,
			z.Any("duty", k.Duty),
			z.Any("pubkey", k.PubKey),
			z.Int("share_idx", shareIdx),
			z.Int("curr_sigs_per_share", len(stored)),
			z.Int("max_allowed_sigs_per_share", maxExemptEntriesPerShare),
		)
	}

	stored = append(stored, k)

	// We append one entry at a time and always trim back to the cap, so a single new entry can
	// exceed it by at most one; evict the oldest (this share's signature) in that case.
	if len(stored) > maxExemptEntriesPerShare {
		db.evictExemptShareEntryUnsafe(ctx, stored[0], shareIdx)
		stored = stored[1:]
	}

	db.exemptEntries[ek] = stored
}

// evictExemptShareEntryUnsafe removes the given share's partial signature from the entry at k,
// deleting the entry entirely if no other shares remain. It warns with the evicted data for
// forensics, since eviction only happens when a share exceeds the per-share cap. It assumes db.mu is held.
func (db *MemDB) evictExemptShareEntryUnsafe(ctx context.Context, k key, shareIdx int) {
	// Log the evicted key (not the data) for forensics; this is a hot path, so avoid marshaling.
	log.Warn(ctx, "Evicting oldest exempt partial signature exceeding per-share cap", nil,
		z.Any("duty", k.Duty),
		z.Any("pubkey", k.PubKey),
		z.Int("share_idx", shareIdx),
		z.Int("max_allowed_sigs_per_share", maxExemptEntriesPerShare),
	)

	sigs := db.entries[k]

	remaining := sigs[:0]
	for _, sig := range sigs {
		if sig.ShareIdx != shareIdx {
			remaining = append(remaining, sig)
		}
	}

	if len(remaining) == 0 {
		delete(db.entries, k)
	} else {
		db.entries[k] = remaining
	}
}
