// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb

import (
	"context"
	"fmt"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// MemDBV2 is a basic memory implementation of core.AggSigDB.
type MemDBV2 struct {
	sync.Mutex
	data       sync.Map // map[memDBKey]core.SignedData
	keysByDuty sync.Map // map[core.Duty][]memDBKey,  Key index by duty for fast deletion.
	deadliner  core.Deadliner

	// storeSig signals when a new Store has concluded for a given key.
	// Await reads storeSig and observes for a given memDBKey, and will re-send keys that it wasn't
	// looking for, to allow other Await calls to eventually return.
	storeSig chan memDBKey
	closed   chan struct{}
}

// NewMemDBV2 creates a basic memory based AggSigDB.
func NewMemDBV2(deadliner core.Deadliner) *MemDBV2 {
	return &MemDBV2{
		// data, keysByDuty are okay to use without explicit initialization
		deadliner: deadliner,
		closed:    make(chan struct{}),
		storeSig:  make(chan memDBKey),
	}
}

func (m *MemDBV2) store(duty core.Duty, pubKey core.PubKey, data core.SignedData) error {
	data, err := data.Clone()
	if err != nil {
		return err
	}

	_ = m.deadliner.Add(duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	key := memDBKey{duty, pubKey}

	if rawExisting, ok := m.data.Load(key); ok {
		existing, ok := rawExisting.(core.SignedData)
		if !ok {
			return errors.New("data stored in aggsigdb not of core.SignedData type", z.Str("key", fmt.Sprintf("%+v", key)))
		}

		equal, err := dataEqual(existing, data)
		if err != nil {
			return err
		} else if !equal {
			return errors.New("mismatching data")
		}
	} else {
		m.data.Store(key, data)
		rawKbd, _ := m.keysByDuty.Load(duty)

		if rawKbd == nil {
			rawKbd = []memDBKey{}
		}

		kbd, ok := rawKbd.([]memDBKey)
		if !ok {
			return errors.New("indexing key data stored in aggsigdb not of []memDBKey type", z.Str("duty", duty.String()))
		}

		kbd = append(kbd, key)
		m.keysByDuty.Store(duty, kbd)
	}

	go func() {
		m.storeSig <- key
	}()

	return nil
}

func (m *MemDBV2) Store(ctx context.Context, duty core.Duty, set core.SignedDataSet) error {
	m.Lock()
	defer m.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.closed:
		return ErrStopped
	default:
	}

	for pubKey, data := range set {
		if err := m.store(duty, pubKey, data); err != nil {
			return err
		}
	}

	return nil
}

func (m *MemDBV2) Await(ctx context.Context, duty core.Duty, pubKey core.PubKey) (core.SignedData, error) {
	key := memDBKey{duty, pubKey}

	var (
		maybeDataRaw any
		ok           bool
	)

	select {
	case <-m.closed:
		return nil, ErrStopped
	default:
		maybeDataRaw, ok = m.data.Load(key)
	}

	if !ok {
		found := false

		for {
			if found {
				break
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-m.closed:
				return nil, ErrStopped
			case storeSignal := <-m.storeSig:
				if storeSignal != key {
					// not for me, so re-enqueue the store signal in the pipe
					go func() {
						m.storeSig <- storeSignal
					}()

					continue
				}

				maybeDataRaw, ok = m.data.Load(key)
				if !ok {
					return nil, errors.New("got a store signal for key, but data wasn't there", z.Str("key", fmt.Sprintf("%+v", key)))
				}

				found = true
			}
		}
	}

	maybeData, ok := maybeDataRaw.(core.SignedData)
	if !ok {
		return nil, errors.New("data stored in aggsigdb not of core.SignedData type", z.Str("key", fmt.Sprintf("%+v", key)))
	}

	return maybeData.Clone()
}

// Run blocks and runs the database process until the context is cancelled.
func (m *MemDBV2) Run(ctx context.Context) {
	defer close(m.closed)

	for {
		select {
		case duty := <-m.deadliner.C():
			// atomically delete deadlined keys
			m.Lock()

			rawKeys, ok := m.keysByDuty.Load(duty)
			if !ok {
				continue
			}

			keys, ok := rawKeys.([]memDBKey)
			if !ok {
				log.Warn(ctx, "Indexing key data stored in aggsigdb not of []memDBKey type", nil, z.Str("duty", duty.String()))
			}

			for _, key := range keys {
				m.data.Delete(key)
			}

			m.keysByDuty.Delete(duty)

			m.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
