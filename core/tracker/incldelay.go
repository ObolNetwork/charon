// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
)

// inclDelayLag is the number of slots to lag before calculating inclusion delay.
// Half an epoch is good compromise between finality and small gaps on startup.
const inclDelayLag = 16

// dutiesFunc returns the duty definitions for a given duty.
type dutiesFunc func(context.Context, core.Duty) (core.DutyDefinitionSet, error)

// NewInclDelayFunc returns a function that calculates attestation inclusion delay for a block.
//
// Inclusion delay is the average of the distance between the slot a validator’s attestation
// is expected by the network and the slot the attestation is actually included on-chain.
// See https://rated.gitbook.io/rated-documentation/rating-methodologies/ethereum-beacon-chain/network-explorer-definitions/top-screener#inclusion-delay.
func NewInclDelayFunc(eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc) func(context.Context, core.Slot) error {
	return newInclDelayFunc(eth2Cl, dutiesFunc, instrumentAvgDelay)
}

// newInclDelayFunc extends NewInclDelayFunc with abstracted callback.
func newInclDelayFunc(eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc, callback func([]int64)) func(context.Context, core.Slot) error {
	// dutyStartSlot is the first slot we can instrument (since dutiesFunc will not have duties from older slots).
	var (
		dutyStartSlot int64
		dssMutex      sync.Mutex
	)

	// getOrSetStartSlot returns a previously set duty start slot and true or it sets it and returns false.
	getOrSetStartSlot := func(slot int64) (int64, bool) {
		dssMutex.Lock()
		defer dssMutex.Unlock()

		if dutyStartSlot == 0 {
			dutyStartSlot = slot
			return 0, false
		}

		return dutyStartSlot, true
	}

	return func(ctx context.Context, current core.Slot) error {
		// blockSlot the block we want to instrument.
		blockSlot := current.Slot - inclDelayLag

		startSlot, ok := getOrSetStartSlot(current.Slot)
		if !ok { // Set start slot.
			return nil
		} else if blockSlot < startSlot {
			return nil // Still need to wait
		}

		atts, err := eth2Cl.BlockAttestations(ctx, fmt.Sprint(blockSlot))
		if err != nil {
			return err
		}

		var delays []int64
		for _, att := range atts {
			if att == nil || att.Data == nil {
				return errors.New("attestation fields cannot be nil")
			}

			attSlot := att.Data.Slot
			if int64(attSlot) < startSlot {
				continue
			}

			// Get all our duties for this attestation blockSlot
			set, err := dutiesFunc(ctx, core.NewAttesterDuty(int64(attSlot)))
			if errors.Is(err, core.ErrNotFound) {
				continue // No duties for this slot.
			} else if err != nil {
				return err
			}

			// Get all our validator committee indexes for this attestation.
			for _, def := range set {
				duty, ok := def.(core.AttesterDefinition)
				if !ok {
					return errors.New("invalid attester definition")
				}

				if duty.CommitteeIndex != att.Data.Index {
					continue // This duty is for another committee
				}

				if !att.AggregationBits.BitAt(duty.ValidatorCommitteeIndex) {
					continue // We are not included in attestation
					// Note that to track missed attestations, we'd need to keep state of seen attestations.
				}

				delays = append(delays, blockSlot-int64(attSlot))
			}
		}

		if len(delays) > 0 {
			callback(delays)
		}

		return nil
	}
}

// instrumentAvgDelay sets the avg inclusion delay metric.
func instrumentAvgDelay(delays []int64) {
	var sum int64
	for _, delay := range delays {
		sum += delay
	}

	avg := sum / int64(len(delays))
	inclusionDelay.Set(float64(avg))
}
