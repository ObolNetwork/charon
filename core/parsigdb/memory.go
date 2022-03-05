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

package parsigdb

import (
	"context"
	"sync"

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
	mu         sync.Mutex
	intSubs    []func(context.Context, core.Duty, core.ParSignedDataSet) error
	threshSubs []func(context.Context, core.Duty, core.PubKey, []core.ParSignedData) error

	entries   map[key][]core.ParSignedData
	threshold int
}

// SubscribeInternal registers a callback when an internal
// partially signed duty set is stored.
func (db *MemDB) SubscribeInternal(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.intSubs = append(db.intSubs, fn)
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
	if err := db.StoreExternal(ctx, duty, signedSet); err != nil {
		return err
	}

	// Call ParSigEx to exchange partial signed data with all peers.
	for _, sub := range db.intSubs {
		err := sub(ctx, duty, signedSet)
		if err != nil {
			return err
		}
	}

	return nil
}

// StoreExternal stores an externally received partially signed duty data set.
func (db *MemDB) StoreExternal(ctx context.Context, duty core.Duty, signedSet core.ParSignedDataSet) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for pubkey, sig := range signedSet {
		k := key{Duty: duty, PubKey: pubkey}
		sigs := db.entries[k]

		var exists bool
		for _, s := range sigs {
			if s.Index == sig.Index {
				exists = true
				break
			}
		}
		if !exists {
			sigs = append(sigs, sig)
			db.entries[k] = sigs
		}

		// Call the SigAgg component if sufficient signatures have been received.
		if len(sigs) != db.threshold {
			continue
		}

		for _, sub := range db.threshSubs {
			err := sub(ctx, duty, pubkey, sigs)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type key struct {
	Duty   core.Duty
	PubKey core.PubKey
}
