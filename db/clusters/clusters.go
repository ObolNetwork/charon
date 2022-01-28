package clusters

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	cdb "github.com/obolnetwork/charon/db"
	"strings"
)

const prefix = "clusters/"

type Cluster struct {
	ID   uint64
	Hash string
}

type DB interface {
	Get(id uint64) (Cluster, error)
	GetByHash(hash string) (Cluster, error)
	Create(cluster Cluster) (uint64, error)
}

func New(bdb *badger.DB) DB {
	return db{db: bdb}
}

type db struct {
	db *badger.DB
}

func (db db) Get(id uint64) (Cluster, error) {
	var res Cluster

	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(toKey(prefix, id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &res)
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return Cluster{}, cdb.ErrNotFound
	} else if err != nil {
		return Cluster{}, err
	}

	return res, nil
}

func (db db) GetByHash(hash string) (Cluster, error) {
	if _, err := hex.DecodeString(hash); err != nil {
		return Cluster{}, errors.New("invalid cluster hash hex")
	}

	var (
		res   Cluster
		found bool
	)

	err := db.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.IteratorOptions{
			Prefix: toKey(prefix),
		})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if bytes.Equal(item.Key(), toKey(prefix)) {
				continue
			}

			var c Cluster
			err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &c)
			})
			if err != nil {
				return err
			}

			if c.Hash == hash {
				res = c
				found = true
				break
			}
		}

		return nil
	})

	if err != nil {
		return Cluster{}, err
	} else if !found {
		return Cluster{}, cdb.ErrNotFound
	}

	return res, nil
}

func (db db) Create(c Cluster) (uint64, error) {
	if c.ID != 0 {
		return 0, errors.New("cannot create cluster with ID")
	}

	seq, err := db.db.GetSequence(toKey(prefix), 1)
	if err != nil {
		return 0, err
	}

	c.ID, err = seq.Next()
	if err != nil {
		return 0, err
	}

	val, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}

	err = db.db.Update(func(txn *badger.Txn) error {
		e := badger.Entry{
			Key:   toKey(prefix, c.ID),
			Value: val,
		}
		return txn.SetEntry(&e)
	})
	if err != nil {
		return 0, err
	}

	return c.ID, nil
}

func toKey(parts ...interface{}) []byte {
	var sb strings.Builder

	for i, part := range parts {
		if i != 0 {
			sb.WriteString("/")
		}
		sb.WriteString(fmt.Sprint(part))
	}

	return []byte(sb.String())
}
