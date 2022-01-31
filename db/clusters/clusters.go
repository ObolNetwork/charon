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

package clusters

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/dgraph-io/badger/v3"

	"github.com/obolnetwork/charon/db/index"
	"github.com/obolnetwork/charon/runner/tracer"
)

const (
	typeName = "cluster"
	seqKey   = "sequence/" + typeName
)

type Cluster struct {
	ID        uint64
	Hash      string // indexed
	CreatedAt time.Time
}

type CreateReq struct {
	Hash string // indexed
}

var hashIndex = index.Index{
	TypeName:  typeName,
	IndexName: "hash",
	Unique:    true,
	KeyFunc: func(val interface{}) ([]byte, error) {
		cl, ok := val.(Cluster)
		if !ok {
			return nil, errors.New("invalid cluster type")
		}
		return []byte(cl.Hash), nil
	},
	IDFunc: func(val interface{}) (uint64, error) {
		cl, ok := val.(Cluster)
		if !ok {
			return 0, errors.New("invalid cluster type")
		}
		return cl.ID, nil
	},
}

type DB interface {
	Get(ctx context.Context, id uint64) (Cluster, bool, error)
	GetByHash(ctx context.Context, hash string) (Cluster, bool, error)
	Create(ctx context.Context, req CreateReq) (uint64, error)
}

func New(bdb *badger.DB) DB {
	return db{
		db:      bdb,
		nowFunc: time.Now,
	}
}

// NewForT returns a new cluster DB for persisting clusters.
func NewForT(bdb *badger.DB, nowFunc func() time.Time) DB {
	return db{
		db:      bdb,
		nowFunc: nowFunc,
	}
}

type db struct {
	db      *badger.DB
	nowFunc func() time.Time
}

func (db db) Get(ctx context.Context, id uint64) (Cluster, bool, error) {
	_, span := tracer.Start(ctx, "db_clusters_get")
	defer span.End()

	var res Cluster

	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(idKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &res)
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return Cluster{}, false, nil
	} else if err != nil {
		return Cluster{}, false, err
	}

	return res, true, nil
}

func (db db) GetByHash(ctx context.Context, hash string) (Cluster, bool, error) {
	if _, err := hex.DecodeString(hash); err != nil {
		return Cluster{}, false, errors.New("invalid cluster hash hex")
	}

	_, span := tracer.Start(ctx, "db_clusters_getbyhash")
	defer span.End()

	var (
		res   Cluster
		found bool
	)

	err := db.db.View(func(txn *badger.Txn) error {
		id, ok, err := index.GetUnique(ctx, txn, hashIndex, Cluster{Hash: hash})
		if err != nil {
			return err
		} else if !ok {
			return nil
		}

		item, err := txn.Get(idKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return errors.New("indexed key not found")
		} else if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			found = true
			return json.Unmarshal(val, &res)
		})
	})
	if err != nil {
		return Cluster{}, false, err
	} else if !found {
		return Cluster{}, false, nil
	}

	return res, true, nil
}

func (db db) Create(ctx context.Context, req CreateReq) (uint64, error) {
	_, span := tracer.Start(ctx, "db_clusters_create")
	defer span.End()

	// TODO(corver): Cache sequencer in db.
	seq, err := db.db.GetSequence([]byte(seqKey), 1)
	if err != nil {
		return 0, err
	}

	id, err := seq.Next()
	if err != nil {
		return 0, err
	} else if id == 0 {
		// Skip 0 sequence since, start at 1
		id, err = seq.Next()
		if err != nil {
			return 0, err
		}
	}

	c := Cluster{
		ID:        id,
		Hash:      req.Hash,
		CreatedAt: db.nowFunc(), // TODO(corver): Make this testable.
	}

	val, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}

	err = db.db.Update(func(txn *badger.Txn) error {
		err := index.Put(ctx, txn, hashIndex, c)
		if err != nil {
			return err
		}

		e := badger.Entry{
			Key:   idKey(c.ID),
			Value: val,
		}
		return txn.SetEntry(&e)
	})
	if err != nil {
		return 0, err
	}

	return c.ID, nil
}

func idKey(id uint64) []byte {
	return []byte(typeName + "/" + strconv.FormatUint(id, 10))
}
