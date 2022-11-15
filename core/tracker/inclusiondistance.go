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

// epochLag is the number of epochs to lag when calculating inclusion distance (to ensure finality).
const epochLag = 2

type dutiesFunc func(context.Context, core.Duty) (core.DutyDefinitionSet, error)

func InclusionDistance(ctx context.Context, eth2Cl eth2wrap.Client, dutiesFunc dutiesFunc) func(ctx context.Context, slot core.Slot) error {
	var fromSlot int64
	return func(ctx context.Context, current core.Slot) error {
		// We have to wait for epochLag since dutiesFunc will not have duties from older epochs.
		if fromSlot == 0 {
			fromSlot = current.Slot
			return nil
		}

		slot := current.Slot - (epochLag * current.SlotsPerEpoch)
		if slot < fromSlot {
			return nil
		}

		atts, err := eth2Cl.BlockAttestations(ctx, fmt.Sprint(slot))
		if err != nil {
			return err
		}

		maxDist := int64(-1)
		for _, att := range atts {
			attSlot := att.Data.Slot

			// Get all our duties for this attestation slot
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
				}

				distance := slot - int64(attSlot)

				if distance > maxDist {
					maxDist = distance
				}
			}
		}

		// TODO(corver):

		return nil
	}
}
