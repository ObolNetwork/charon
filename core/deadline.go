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
	"sync"
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

// Deadliner provides duty Deadline functionality. The C method isn’t thread safe and
// may only be used by a single goroutine. So, multiple instances are required
// for different components and use cases.
type Deadliner interface {
	// Add adds a duty to be notified of the Deadline via C.
	// Note that duties will be deduplicated and only a single duty will be provided via C.
	Add(duty Duty)

	// C returns the same read channel every time and contains deadlined duties.
	// It should only be called by a single goroutine.
	C() <-chan Duty
}

// Deadline implements the Deadliner interface.
type Deadline struct {
	mu           sync.Mutex
	genesisTime  time.Time
	slotDuration time.Duration

	dutyChan     chan Duty
	deadlineChan chan Duty

	// duties represents a set since duty deduplication is required.
	duties map[Duty]bool
}

// NewDeadliner returns a new instance of Deadline.
// It runs a goroutine which is responsible for reading and storing duties.
// It also sends the deadlined duty to receiver's deadlineChan.
func NewDeadliner(ctx context.Context, eth2Cl slotTimeProvider) (*Deadline, error) {
	genesis, err := eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}

	duration, err := eth2Cl.SlotDuration(ctx)
	if err != nil {
		return nil, err
	}

	d := &Deadline{
		genesisTime:  genesis,
		slotDuration: duration,
		dutyChan:     make(chan Duty),
		deadlineChan: make(chan Duty),
		duties:       make(map[Duty]bool),
	}

	go func() {
		var (
			deadlineTimer <-chan time.Time
			minDuty       Duty
		)

		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-d.dutyChan:
				if minDuty.Type == DutyUnknown {
					// Initialise minDuty and deadlineTimer
					minDuty = duty
					deadlineTimer = time.After(time.Until(d.deadlineTime(minDuty)))
				}
				d.duties[duty] = true
			case <-deadlineTimer:
				// Send deadlined duty to receiver
				d.deadlineChan <- minDuty

				// Delete duty whose deadline has passed
				delete(d.duties, minDuty)

				// New min duty for next deadline
				md, ok := d.getMinDuty()
				if !ok {
					continue
				}
				minDuty = md
				deadlineTimer = time.After(time.Until(d.deadlineTime(minDuty)))
			}
		}
	}()

	return d, nil
}

// Add adds a duty to be notified of the deadline.
func (d *Deadline) Add(duty Duty) {
	d.dutyChan <- duty
}

// C returns the deadline channel.
func (d *Deadline) C() <-chan Duty {
	return d.deadlineChan
}

// getMinDuty gets the duty to process next.
// It selects duty with minimum slot. If slots are equal then it selects the duty with minimum DutyType.
func (d *Deadline) getMinDuty() (Duty, bool) {
	minDuty := Duty{Slot: math.MaxInt64, Type: dutySentinel}
	for duty := range d.duties {
		if duty.Slot < minDuty.Slot || ((duty.Slot == minDuty.Slot) && (duty.Type < minDuty.Type)) {
			minDuty = duty
		}
	}

	if minDuty.Slot == math.MaxInt64 {
		return minDuty, false
	}

	return minDuty, true
}

// deadlineTime returns the deadline time of the duty.
func (d *Deadline) deadlineTime(duty Duty) time.Time {
	if duty.Type == DutyExit {
		// Do not timeout exit duties.
		return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	start := d.genesisTime.Add(d.slotDuration * time.Duration(duty.Slot))
	end := start.Add(d.slotDuration * time.Duration(lateFactor))

	return end
}

// NewDutyDeadlineFunc returns the function that provides duty deadlines.
// TODO(dhruv): replace "NewDutyDeadlineFunc" with above deadliner implementation wherever used.
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
			return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		}

		start := genesis.Add(duration * time.Duration(duty.Slot))
		end := start.Add(duration * time.Duration(lateFactor))

		return end
	}, nil
}
