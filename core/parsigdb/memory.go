// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"bytes"
	"context"
	"encoding/json"
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
		threshold:  threshold,
		deadliner:  deadliner,
	}
}

// MemDB is a placeholder in-memory partial signature database.
// It will be replaced with a BadgerDB implementation.
type MemDB struct {
	mu           sync.Mutex
	internalSubs []func(context.Context, core.Duty, core.ParSignedDataSet) error
	threshSubs   []func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error

	entries    map[key][]core.ParSignedData
	keysByDuty map[core.Duty][]key
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
	_ = db.deadliner.Add(duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	output := make(map[core.PubKey][]core.ParSignedData)

	for pubkey, sig := range signedSet {
		sigs, ok, err := db.store(key{Duty: duty, PubKey: pubkey}, sig)
		if err != nil {
			return err
		} else if !ok {
			log.Debug(ctx, "Partial signed data ignored since duplicate")

			continue
		}

		log.Debug(ctx, "Partial signed data stored",
			z.Int("count", len(sigs)),
			z.Any("pubkey", pubkey))

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
	db.keysByDuty[k.Duty] = append(db.keysByDuty[k.Duty], k)

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
