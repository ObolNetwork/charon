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

package core

import (
	"context"
	"math"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"

	"github.com/obolnetwork/charon/app/errors"
)

// lateFactor defines the number of slots duties may be late.
// See https://pintail.xyz/posts/modelling-the-impact-of-altair/#proposer-and-delay-rewards.
const lateFactor = 5

// slotTimeProvider defines eth2client interface for resolving slot start times.
type slotTimeProvider interface {
	eth2client.GenesisTimeProvider
	eth2client.SlotDurationProvider
}

// NewDutyDeadlineFunc returns the function that provides duty deadlines.
func NewDutyDeadlineFunc(ctx context.Context, eth2Svc eth2client.Service) (func(Duty) time.Time, error) {
	eth2Cl, ok := eth2Svc.(slotTimeProvider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	duration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	return func(duty Duty) time.Time {
		if duty.Type == DutyExit {
			// Do not timeout exit duties.
			return time.Unix(math.MaxInt64, 0)
		}

		start := genesis.Add(duration * time.Duration(duty.Slot))
		end := start.Add(duration * time.Duration(lateFactor))

		return end
	}, nil
}
