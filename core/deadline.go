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
	dutyChan     chan Duty
	deadlineChan chan Duty
	quit         chan struct{}
	deadlineFunc func(Duty) time.Time
}

// NewDeadliner returns a new instance of Deadline.
// It runs a goroutine which is responsible for reading and storing duties,
// and sending the deadlined duty to receiver's deadlineChan.
func NewDeadliner(ctx context.Context, deadlineFunc func(Duty) time.Time) (*Deadline, error) {
	d := &Deadline{
		dutyChan:     make(chan Duty),
		deadlineChan: make(chan Duty),
		quit:         make(chan struct{}),
		deadlineFunc: deadlineFunc,
	}

	// If duties arrive out of order, it should update the timer if it hasn't elapsed

	go func() {
		var (
			currDuty     Duty
			currDeadline time.Time
			currTimer    = time.NewTimer(0)
			duties       = make(map[Duty]bool)
		)

		defer func() {
			close(d.quit)
			currTimer.Stop()
		}()

		setCurrState := func(duty Duty) {
			currDuty = duty
			currDeadline = d.deadlineFunc(duty)
			currTimer = time.NewTimer(time.Until(currDeadline))
		}

		for {
			select {
			case <-ctx.Done():
				return
			case duty := <-d.dutyChan:
				if currDeadline.IsZero() {
					// Initialise if there are no duties.
					setCurrState(duty)
				} else if currDeadline.After(d.deadlineFunc(duty)) {
					// Set current deadline to the latest one.
					currTimer.Stop()
					setCurrState(duty)
				}

				duties[duty] = true
			case <-currTimer.C:
				// Send deadlined duty to receiver
				d.deadlineChan <- currDuty

				// Delete duty whose deadline has passed
				delete(duties, currDuty)

				// New current duty for next deadline
				duty, ok := getCurrDuty(duties, d.deadlineFunc)
				if !ok {
					continue
				}

				setCurrState(duty)
			}
		}
	}()

	return d, nil
}

// Add adds a duty to be notified of the deadline.
func (d *Deadline) Add(duty Duty) {
	select {
	case <-d.quit:
		return
	default:
		d.dutyChan <- duty
	}
}

// C returns the deadline channel.
func (d *Deadline) C() <-chan Duty {
	return d.deadlineChan
}

// getCurrDuty gets the duty to process next. It selects duty with the latest deadline.
func getCurrDuty(duties map[Duty]bool, deadlineFunc func(duty Duty) time.Time) (Duty, bool) {
	var currDuty Duty
	currDeadline := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	for duty := range duties {
		dutyDeadline := deadlineFunc(duty)
		if currDeadline.After(dutyDeadline) {
			currDuty = duty
			currDeadline = dutyDeadline
		}
	}

	if currDuty.Type == DutyUnknown {
		return Duty{}, false
	}

	return currDuty, true
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
			return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		}

		start := genesis.Add(duration * time.Duration(duty.Slot))
		end := start.Add(duration * time.Duration(lateFactor))

		return end
	}, nil
}
