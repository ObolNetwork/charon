// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// NewMemDB returns a new in-memory partial signature database instance.
func NewMemDB(threshold int, deadliner core.Deadliner) *MemDB {
	return &MemDB{
		entries:    make(map[key][]core.ParSignedData),
		keysByDuty: make(map[core.Duty][]key),
		notified:   make(map[key]bool),
		threshold:  threshold,
		deadliner:  deadliner,
	}
}

// MemDB implements core.ParSigDB using an in-memory data store.
type MemDB struct {
	mu           sync.Mutex
	internalSubs []func(context.Context, core.Duty, core.ParSignedDataSet) error
	threshSubs   []func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error

	entries    map[key][]core.ParSignedData
	keysByDuty map[core.Duty][]key
	notified   map[key]bool // Track which keys have reached threshold to avoid duplicate notifications
	threshold  int
	deadliner  core.Deadliner
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

	// Copy subscribers under lock to avoid race conditions.
	db.mu.Lock()
	subs := make([]func(context.Context, core.Duty, core.ParSignedDataSet) error, len(db.internalSubs))
	copy(subs, db.internalSubs)
	db.mu.Unlock()

	// Call internalSubs (which includes ParSigEx to exchange partial signed data with all peers).
	for _, sub := range subs {
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
	ctx = log.WithCtx(ctx, z.Any("duty", duty))
	_ = db.deadliner.Add(duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	// Collect keys that reached threshold (batch processing to reduce lock contention)
	type thresholdReached struct {
		key   key
		psigs []core.ParSignedData
	}

	var reached []thresholdReached

	for pubkey, sig := range signedSet {
		k := key{Duty: duty, PubKey: pubkey}

		sigs, ok, err := db.store(k, sig)
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

		reached = append(reached, thresholdReached{key: k, psigs: psigs})
	}

	if len(reached) == 0 {
		return nil
	}

	// Single lock to check and update all notifications at once
	db.mu.Lock()

	output := make(map[core.PubKey][]core.ParSignedData)

	for _, r := range reached {
		if !db.notified[r.key] {
			db.notified[r.key] = true
			output[r.key.PubKey] = r.psigs
		}
	}

	db.mu.Unlock()

	if len(output) == 0 {
		return nil
	}

	// Copy subscribers under lock to avoid race conditions.
	db.mu.Lock()
	subs := make([]func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error, len(db.threshSubs))
	copy(subs, db.threshSubs)
	db.mu.Unlock()

	// Call the threshSubs (which includes SigAgg component)
	for _, sub := range subs {
		// Clone before calling each subscriber.
		cloned, err := cloneWithError(output)
		if err != nil {
			return err
		}

		if err := sub(ctx, duty, cloned); err != nil {
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
				delete(db.notified, key)
			}

			delete(db.keysByDuty, duty)
			db.mu.Unlock()
		}
	}
}

// store returns true if the value was added to the list of signatures at the provided key
// and returns a copy of the resulting list.
func (db *MemDB) store(k key, value core.ParSignedData) ([]core.ParSignedData, bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

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

	// Only append key to keysByDuty if this is the first signature for this key.
	// This prevents duplicate keys accumulating in keysByDuty.
	if len(db.entries[k]) == 1 {
		db.keysByDuty[k.Duty] = append(db.keysByDuty[k.Duty], k)
	}

	if k.Duty.Type == core.DutyExit {
		exitCounter.WithLabelValues(k.PubKey.String()).Inc()
	}

	return append([]core.ParSignedData(nil), db.entries[k]...), true, nil
}

// cloneWithError returns a deep copy of the provided map or an error.
func cloneWithError(output map[core.PubKey][]core.ParSignedData) (map[core.PubKey][]core.ParSignedData, error) {
	result := make(map[core.PubKey][]core.ParSignedData)
	for pubkey, sigs := range output {
		var clones []core.ParSignedData

		for _, sig := range sigs {
			clone, err := sig.Clone()
			if err != nil {
				return nil, errors.Wrap(err, "clone partial signature")
			}

			clones = append(clones, clone)
		}

		result[pubkey] = clones
	}

	return result, nil
}

// getThresholdMatching returns true and threshold number of partial signed data with identical data or false.
func getThresholdMatching(typ core.DutyType, sigs []core.ParSignedData, threshold int) ([]core.ParSignedData, bool, error) {
	if len(sigs) < threshold {
		return nil, false, nil
	}

	if typ == core.DutySignature {
		// Signatures do not support message roots.
		// Return exactly threshold number of signatures.
		return sigs[:threshold], true, nil
	}

	sigsByMsgRoot := make(map[[32]byte][]core.ParSignedData) // map[Root][]ParSignedData

	for _, sig := range sigs {
		root, err := sig.MessageRoot()
		if err != nil {
			return nil, false, err
		}

		sigsByMsgRoot[root] = append(sigsByMsgRoot[root], sig)
	}

	// Return true if we have at least threshold number of signatures with the same root.
	// Return exactly threshold signatures to be consistent.
	// Sort by ShareIdx for deterministic output.
	for _, set := range sigsByMsgRoot {
		if len(set) >= threshold {
			// Sort by share index for deterministic, reproducible behavior
			sort.Slice(set, func(i, j int) bool {
				return set[i].ShareIdx < set[j].ShareIdx
			})

			return set[:threshold], true, nil
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
