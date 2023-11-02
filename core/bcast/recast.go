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
	subs           []func(context.Context, core.Duty, core.SignedDataSet) error
}

// Subscribe subscribes to rebroadcasted duties.
func (r *Recaster) Subscribe(sub func(context.Context, core.Duty, core.SignedDataSet) error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.subs = append(r.subs, sub)
}

// Store stores aggregate signed duty registrations for rebroadcasting.
func (r *Recaster) Store(ctx context.Context, duty core.Duty,
	set core.SignedDataSet,
) error {
	if duty.Type != core.DutyBuilderRegistration {
		return nil
	}

	for pubkey, aggData := range set {
		if err := r.store(ctx, duty, pubkey, aggData); err != nil {
			return err
		}
	}

	return nil
}

// store stores aggregate signed duty registrations for rebroadcasting.
func (r *Recaster) store(_ context.Context, duty core.Duty,
	pubkey core.PubKey, aggData core.SignedData,
) error {
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

	activeVals, err := r.activeValsFunc(ctx)
	if err != nil {
		return errors.Wrap(err, "get active validator")
	}

	// Copy locked things before doing IO.
	var (
		clonedSets = make(map[core.Duty]map[core.PubKey]core.SignedData)
		clonedSubs []func(context.Context, core.Duty, core.SignedDataSet) error
	)

	r.mu.Lock()
	clonedSubs = append(clonedSubs, r.subs...)
	for pubkey, tuple := range r.tuples {
		ethPk, err := pubkey.ToETH2()
		if err != nil {
			log.Error(ctx, "Can't convert pubkey to eth2 format", err)
			continue
		}

		if _, found := activeVals[ethPk]; !found {
			continue
		}

		set, ok := clonedSets[tuple.duty]
		if !ok {
			set = make(core.SignedDataSet)
			clonedSets[tuple.duty] = set
		}
		set[pubkey] = tuple.aggData
	}
	r.mu.Unlock()

	for duty, set := range clonedSets {
		dutyCtx := log.WithCtx(ctx, z.Any("duty", duty))

		for _, sub := range clonedSubs {
			err := sub(dutyCtx, duty, set)
			if err != nil {
				log.Error(dutyCtx, "Rebroadcast duty error (will retry next epoch)", err)
				incRegCounter(duty, recastErrors)
			}
			incRegCounter(duty, recastTotal)
		}
	}

	return nil
}

// incRegCounter increments the registration counter if applicable.
func incRegCounter(duty core.Duty, counterVec *prometheus.CounterVec) {
	if duty.Type != core.DutyBuilderRegistration {
		return
	}

	source := regSourcePregen
	if duty.Slot > 0 {
		source = regSourceDownstream
	}

	counterVec.WithLabelValues(source).Inc()
}
