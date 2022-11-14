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
func NewMemDB(threshold int) *MemDB {
	return &MemDB{
		entries:   make(map[key][]core.ParSignedData),
		threshold: threshold,
	}
}

// MemDB is a placeholder in-memory partial signature database.
// It will be replaced with a BadgerDB implementation.
type MemDB struct {
	mu           sync.Mutex
	internalSubs []func(context.Context, core.Duty, core.ParSignedDataSet) error
	threshSubs   []func(context.Context, core.Duty, core.PubKey, []core.ParSignedData) error

	entries   map[key][]core.ParSignedData
	threshold int
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
func (db *MemDB) SubscribeThreshold(fn func(context.Context, core.Duty, core.PubKey, []core.ParSignedData) error) {
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
	thresholdReached := make(map[core.PubKey]bool)
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
		} else if !ok || thresholdReached[pubkey] {
			continue
		}

		// Call the threshSubs (which includes SigAgg component)
		for _, sub := range db.threshSubs {
			// Clone before calling each subscriber.
			var clones []core.ParSignedData
			for _, psig := range psigs {
				clone, err := psig.Clone()
				if err != nil {
					return err
				}
				clones = append(clones, clone)
			}

			if err := sub(ctx, duty, pubkey, clones); err != nil {
				return err
			}
		}

		thresholdReached[pubkey] = true
	}

	return nil
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

	if k.Duty.Type == core.DutyExit {
		exitCounter.WithLabelValues(k.PubKey.String()).Inc()
	}

	return append([]core.ParSignedData(nil), db.entries[k]...), true, nil
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

	sigsByMsgRoot := make(map[[32]byte][]core.ParSignedData)
	for _, sig := range sigs {
		root, err := sig.MessageRoot()
		if err != nil {
			return nil, false, errors.Wrap(err, "message root")
		}

		// Find the first set of length threshold
		set := sigsByMsgRoot[root]
		set = append(set, sig)

		if len(set) == threshold {
			return set, true, nil
		}

		sigsByMsgRoot[root] = set
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
