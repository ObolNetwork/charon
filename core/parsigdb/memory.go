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
		err := sub(ctx, duty, signedSet)
		if err != nil {
			return err
		}
	}

	return nil
}

// StoreExternal stores an externally received partially signed duty data set.
func (db *MemDB) StoreExternal(ctx context.Context, duty core.Duty, signedSet core.ParSignedDataSet) error {
	for pubkey, sig := range signedSet {
		sigs, ok, err := db.store(key{Duty: duty, PubKey: pubkey}, sig)
		if err != nil {
			return err
		} else if !ok {
			log.Debug(ctx, "Not storing duplicate partial signed data",
				z.Any("pubkey", pubkey), z.Int("share_idx", sig.ShareIdx))

			continue
		}

		log.Debug(ctx, "Stored partial signed data",
			z.Any("pubkey", pubkey), z.Int("count", len(sigs)), z.Int("share_idx", sig.ShareIdx))

		// Call the threshSubs (which includes SigAgg component) if sufficient signatures have been received.
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

// store returns true if the value was added to the list of signatures at the provided key
// and returns a copy of the resulting list.
func (db *MemDB) store(k key, value core.ParSignedData) ([]core.ParSignedData, bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	for _, s := range db.entries[k] {
		if s.ShareIdx == value.ShareIdx {
			equal, err := dataEqual(s, value)
			if err != nil {
				return nil, false, err
			} else if !equal {
				return nil, false, errors.New("mismatching partial signed data",
					z.Any("pubkey", k.PubKey), z.Int("share_idx", s.ShareIdx))
			}

			return nil, false, nil
		}
	}

	db.entries[k] = append(db.entries[k], value)

	return append([]core.ParSignedData(nil), db.entries[k]...), true, nil
}

func dataEqual(x, y core.ParSignedData) (bool, error) {
	xjson, err := x.MarshalJSON()
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}
	yjson, err := y.MarshalJSON()
	if err != nil {
		return false, errors.Wrap(err, "marshal data")
	}

	return bytes.Equal(xjson, yjson), nil
}

type key struct {
	Duty   core.Duty
	PubKey core.PubKey
}
