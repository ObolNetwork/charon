// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package aggsigdb

import (
	"context"
	"runtime"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
)

// MemDBV2 is a basic memory implementation of core.AggSigDB.
type MemDBV2 struct {
	sync.RWMutex
	data       map[memDBKey]core.SignedData
	keysByDuty map[core.Duty][]memDBKey // Key index by duty for fast deletion.
	deadliner  core.Deadliner
	closed     chan struct{}
}

// NewMemDBV2 creates a basic memory based AggSigDB.
func NewMemDBV2(deadliner core.Deadliner) *MemDBV2 {
	return &MemDBV2{
		// data, keysByDuty are okay to use without explicit initialization
		deadliner:  deadliner,
		closed:     make(chan struct{}),
		data:       map[memDBKey]core.SignedData{},
		keysByDuty: map[core.Duty][]memDBKey{},
	}
}

func (m *MemDBV2) store(duty core.Duty, pubKey core.PubKey, data core.SignedData) error {
	data, err := data.Clone()
	if err != nil {
		return err
	}

	_ = m.deadliner.Add(duty) // TODO(corver): Distinguish between no deadline supported vs already expired.

	key := memDBKey{duty, pubKey}

	if existing, ok := m.data[key]; ok {
		equal, err := dataEqual(existing, data)
		if err != nil {
			return err
		} else if !equal {
			return errors.New("mismatching data")
		}
	} else {
		m.data[key] = data
		m.keysByDuty[duty] = append(m.keysByDuty[duty], key)
	}

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
	errMustLoop := errors.New("still needs loop")

	query := func() (core.SignedData, error) {
		m.RLock()
		defer m.RUnlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.closed:
			return nil, ErrStopped
		default:
			data, ok := m.data[memDBKey{duty, pubKey}]
			if !ok {
				return nil, errMustLoop
			}

			return data.Clone()
		}
	}

	for {
		data, err := query()
		if err != nil {
			if !errors.Is(err, errMustLoop) {
				return nil, err
			}

			runtime.Gosched() // yield to runtime to avoid trashing

			continue
		}

		return data, nil
	}
}

// Run blocks and runs the database process until the context is cancelled.
func (m *MemDBV2) Run(ctx context.Context) {
	defer close(m.closed)

	deadlineDel := func(duty core.Duty) {
		// atomically delete deadlined keys
		m.Lock()
		defer m.Unlock()

		keys, ok := m.keysByDuty[duty]
		if !ok {
			return
		}

		for _, key := range keys {
			delete(m.data, key)
		}

		delete(m.keysByDuty, duty)
	}

	for {
		select {
		case duty := <-m.deadliner.C():
			deadlineDel(duty)
		case <-ctx.Done():
			return
		}
	}
}
