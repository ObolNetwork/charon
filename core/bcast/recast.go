// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"sync"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	// regSourcePregen defines a pregenerated registration.
	regSourcePregen = "pregen"
	// regSourceDownstream defines a registration submitted by a downstream VC.
	regSourceDownstream = "downstream"
)

type recastTuple struct {
	duty    core.Duty
	aggData core.SignedData
}

// NewRecaster returns a new recaster.
func NewRecaster(activeValsFunc func(context.Context) (map[eth2p0.BLSPubKey]struct{}, error)) (*Recaster, error) {
	if activeValsFunc == nil {
		return nil, errors.New("active validators provider is nil")
	}

	return &Recaster{
		tuples:         make(map[core.PubKey]recastTuple),
		activeValsFunc: activeValsFunc,
	}, nil
}

// Recaster rebroadcasts core.DutyBuilderRegistration aggregate signatures every epoch.
type Recaster struct {
	mu             sync.Mutex
	tuples         map[core.PubKey]recastTuple
	activeValsFunc func(context.Context) (map[eth2p0.BLSPubKey]struct{}, error)
	subs           []func(context.Context, core.Duty, core.PubKey, core.SignedData) error
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

	activeVals, err := r.activeValsFunc(ctx)
	if err != nil {
		return errors.Wrap(err, "get active validator")
	}

	for pubkey, tuple := range clonedTuples {
		ctx := log.WithCtx(ctx, z.Any("duty", tuple.duty))

		ethPk, err := pubkey.ToETH2()
		if err != nil {
			log.Error(ctx, "Can't convert pubkey to eth2 format", err)
			continue
		}

		if _, found := activeVals[ethPk]; !found {
			log.Debug(ctx, "Ignoring non-active validator", z.Str("pubkey", pubkey.String()))
			continue
		}

		for _, sub := range clonedSubs {
			err := sub(ctx, tuple.duty, pubkey, tuple.aggData)
			if err != nil {
				log.Error(ctx, "Rebroadcast duty error (will retry next epoch)", err)
				incRegCounter(tuple, recastErrors)
			}
			incRegCounter(tuple, recastTotal)
		}
	}

	return nil
}

// incRegCounter increments the registration counter if applicable.
func incRegCounter(tuple recastTuple, counterVec *prometheus.CounterVec) {
	if tuple.duty.Type != core.DutyBuilderRegistration {
		return
	}

	source := regSourcePregen
	if tuple.duty.Slot > 0 {
		source = regSourceDownstream
	}

	counterVec.WithLabelValues(source).Inc()
}
