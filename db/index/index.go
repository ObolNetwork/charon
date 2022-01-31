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

// Package index provides types and functions to define, update and query indexes stored in badger.
// It uses roaring bitmaps for index values for improved performance. This does require that indexed keys to
// be of type uint64.

package index

import (
	"bytes"
	"context"
	"errors"

	"github.com/dgraph-io/badger/v3"
	"github.com/dgraph-io/sroar"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/runner/tracer"
)

const prefix = "index/"

var ErrDupUnique = errors.New("duplicate unique index detected")

type Index struct {
	TypeName  string // e.g. cluster
	IndexName string // e.g. by_hash_and_created_at
	Unique    bool
	KeyFunc   func(val interface{}) ([]byte, error)
	IDFunc    func(val interface{}) (uint64, error)
}

func Put(ctx context.Context, txn *badger.Txn, index Index, val interface{}) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "badger_index_put")
	defer span.End()

	key, err := toKey(index, val)
	if err != nil {
		return err
	}

	var bm *sroar.Bitmap

	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		bm = sroar.NewBitmap()
	} else if err != nil {
		return err
	} else {
		err := item.Value(func(val []byte) error {
			bm = sroar.FromBufferWithCopy(val)
			return nil
		})
		if err != nil {
			return err
		}
	}

	id, err := index.IDFunc(val)
	if err != nil {
		return err
	}

	bm.Set(id)

	if index.Unique && bm.GetCardinality() > 1 {
		return ErrDupUnique
	}

	return txn.Set(key, bm.ToBuffer())
}

func GetUnique(ctx context.Context, txn *badger.Txn, index Index, val interface{}) (uint64, bool, error) {
	ids, err := Get(ctx, txn, index, val)
	if err != nil {
		return 0, false, err
	} else if len(ids) > 1 {
		return 0, false, ErrDupUnique
	} else if len(ids) == 0 {
		return 0, false, nil
	}

	return ids[0], true, nil
}

func Get(ctx context.Context, txn *badger.Txn, index Index, val interface{}) ([]uint64, error) {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "badger_index_get")
	defer span.End()

	key, err := toKey(index, val)
	if err != nil {
		return nil, err
	}

	var bm *sroar.Bitmap

	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	err = item.Value(func(val []byte) error {
		bm = sroar.FromBufferWithCopy(val)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return bm.ToArray(), nil
}

// ToKey returns the index key for the given type and fields.
func toKey(index Index, val interface{}) ([]byte, error) {
	key, err := index.KeyFunc(val)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(prefix)
	buf.WriteString(index.TypeName)
	buf.WriteString("/")
	buf.WriteString(index.IndexName)
	buf.WriteString("/")
	buf.Write(key)

	return buf.Bytes(), nil
}
