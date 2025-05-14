// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"testing"
	"time"

	"github.com/obolnetwork/charon/eth2util"
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
func NewDutyGater(opts ...func(*dutyGaterOptions)) (DutyGaterFunc, error) {
	o := dutyGaterOptions{
		allowedFutureEpochs: defaultAllowedFutureEpochs,
		nowFunc:             time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}

	network := eth2util.CurrentNetwork()

	return func(duty Duty) bool {
		if !duty.Type.Valid() {
			return false
		}

		currentSlot := o.nowFunc().Sub(network.GetGenesisTimestamp()) / network.SlotDuration
		currentEpoch := uint64(currentSlot) / network.SlotsPerEpoch
		dutyEpoch := duty.Slot / network.SlotsPerEpoch

		return dutyEpoch <= currentEpoch+uint64(o.allowedFutureEpochs)
	}, nil
}
