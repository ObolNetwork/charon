// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
)

const defaultAllowedFutureEpochs = 2

// DutyGaterFunc is a function that returns true if the duty is allowed to be processed.
// It checks whether duties received from peers over the wire are too far in the future
// or whether the type is invalid. It doesn't check whether the duty
// is in the past, that is done by Deadliner.
type DutyGaterFunc func(Duty) bool

// WithDutyGaterForT returns a function that sets the nowFunc and allowedFutureEpochs in
// order to create a DutyGaterFunc for use in tests.
func WithDutyGaterForT(_ *testing.T, nowFunc func() time.Time, allowedFutureEpochs int) func(*dutyGaterOptions) {
	return func(o *dutyGaterOptions) {
		o.nowFunc = nowFunc
		o.allowedFutureEpochs = allowedFutureEpochs
	}
}

type dutyGaterOptions struct {
	allowedFutureEpochs int
	nowFunc             func() time.Time
}

// NewDutyGater returns a new instance of DutyGaterFunc.
func NewDutyGater(ctx context.Context, eth2Cl eth2wrap.Client, opts ...func(*dutyGaterOptions)) (DutyGaterFunc, error) {
	o := dutyGaterOptions{
		allowedFutureEpochs: defaultAllowedFutureEpochs,
		nowFunc:             time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}

	genesisTime, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	eth2Resp, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}

	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return nil, errors.New("fetch slot duration")
	}

	slotsPerEpoch, ok := eth2Resp.Data["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return nil, errors.New("fetch slots per epoch")
	}

	return func(duty Duty) bool {
		if !duty.Type.Valid() {
			return false
		}

		currentSlot := o.nowFunc().Sub(genesisTime) / slotDuration
		currentEpoch := uint64(currentSlot) / slotsPerEpoch

		dutyEpoch := duty.Slot / slotsPerEpoch

		return dutyEpoch <= currentEpoch+uint64(o.allowedFutureEpochs)
	}, nil
}
