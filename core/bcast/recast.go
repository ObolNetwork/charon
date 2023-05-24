// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

type recastTuple struct {
	duty    core.Duty
	aggData core.SignedData
}

// NewRecaster returns a new recaster.
func NewRecaster() *Recaster {
	return &Recaster{
		tuples: make(map[core.PubKey]recastTuple),
	}
}

// Recaster rebroadcasts core.DutyBuilderRegistration aggregate signatures every epoch.
type Recaster struct {
	mu     sync.Mutex
	tuples map[core.PubKey]recastTuple
	subs   []func(context.Context, core.Duty, core.PubKey, core.SignedData) error
}

// Subscribe subscribes to rebroadcasted duties.
func (r *Recaster) Subscribe(sub func(context.Context, core.Duty, core.PubKey, core.SignedData) error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.subs = append(r.subs, sub)
}

// Store stores aggregate signed duty registrations for rebroadcasting.
func (r *Recaster) Store(_ context.Context, duty core.Duty,
	pubkey core.PubKey, aggData core.SignedData,
) error {
	if duty.Type != core.DutyBuilderRegistration {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tuple, ok := r.tuples[pubkey]
	if ok && tuple.duty.Slot >= duty.Slot {
		// Not storing duplicate or older registration.
		return nil
	}

	// Clone before storing.
	data, err := aggData.Clone()
	if err != nil {
		return err
	}

	r.tuples[pubkey] = recastTuple{
		duty:    duty,
		aggData: data,
	}

	// Add unique registrations count.
	recastRegistrationCounter.WithLabelValues(pubkey.String()).Inc()

	return nil
}

// SlotTicked is called when new slots tick.
func (r *Recaster) SlotTicked(ctx context.Context, slot core.Slot) error {
	if !slot.FirstInEpoch() {
		return nil
	}
	ctx = log.WithTopic(ctx, "bcast")

	// Copy locked things before doing IO.
	var (
		clonedTuples = make(map[core.PubKey]recastTuple)
		clonedSubs   []func(context.Context, core.Duty, core.PubKey, core.SignedData) error
	)

	r.mu.Lock()
	clonedSubs = append(clonedSubs, r.subs...)
	for k, v := range r.tuples {
		clonedTuples[k] = v
	}
	r.mu.Unlock()

	for pubkey, tuple := range clonedTuples {
		ctx := log.WithCtx(ctx, z.Any("duty", tuple.duty))
		for _, sub := range clonedSubs {
			err := sub(ctx, tuple.duty, pubkey, tuple.aggData)
			if err != nil {
				log.Error(ctx, "Rebroadcast duty error (will retry next epoch)", err)
			}
		}
	}

	return nil
}
