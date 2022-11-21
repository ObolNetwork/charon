// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package tracker

import (
	"context"
	"fmt"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
)

// epochLag is the number of epochs to lag when calculating inclusion delay (to ensure finality).
const epochLag = 1

// dutiesFunc returns the duty definitions for a given duty.
type dutiesFunc func(context.Context, core.Duty) (core.DutyDefinitionSet, error)

// NewInclDelayFunc returns a function that calculates this cluster's attestation inclusion delay for a block.
func NewInclDelayFunc(eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc) func(context.Context, core.Slot) error {
	return newInclDelayFunc(eth2Cl, dutiesFunc, func(delays []int64) {
		var sum int64
		for _, delay := range delays {
			sum += delay
		}

		avg := sum / int64(len(delays))
		inclusionDelay.Set(float64(avg))
	})
}

// newInclDelayFunc extends NewInclDelayFunc with abstracted callback.
func newInclDelayFunc(eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc, callback func([]int64)) func(context.Context, core.Slot) error {
	var fromSlot int64
	return func(ctx context.Context, current core.Slot) error {
		// We have to wait for epochLag since dutiesFunc will not have duties from older epochs.
		if fromSlot == 0 {
			fromSlot = current.Slot
			return nil
		}

		blockSlot := current.Slot - (epochLag * current.SlotsPerEpoch)
		if blockSlot < fromSlot {
			return nil
		}

		atts, err := eth2Cl.BlockAttestations(ctx, fmt.Sprint(blockSlot))
		if err != nil {
			return err
		}

		var delays []int64
		for _, att := range atts {
			attSlot := att.Data.Slot
			if int64(attSlot) < fromSlot {
				continue
			}

			// Get all our duties for this attestation blockSlot
			set, err := dutiesFunc(ctx, core.NewAttesterDuty(int64(attSlot)))
			if err != nil {
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
					// Note to track missed attestations, we'd need to keep state of seen attestations.
				}

				delays = append(delays, blockSlot-int64(attSlot))
			}
		}

		callback(delays)

		return nil
	}
}
