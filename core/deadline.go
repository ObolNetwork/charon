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
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
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
	// Add returns true if the duty was added for future deadline scheduling. It is idempotent
	// and returns true if the duty was previously added and still awaits deadline scheduling. It
	// returns false if the duty has already expired and cannot therefore be added for scheduling.
	Add(duty Duty) bool

	// C returns the same read channel every time and contains deadlined duties.
	// It should only be called by a single goroutine.
	C() <-chan Duty
}

// deadlinerInput represents the input to inputChan.
type deadlineInput struct {
	duty    Duty
	success chan<- bool
}

// deadliner implements the Deadliner interface.
type deadliner struct {
	inputChan    chan deadlineInput
	deadlineChan chan Duty
	clock        clockwork.Clock
	quit         chan struct{}
}

// NewDeadlinerForT returns a Deadline for use in tests.
func NewDeadlinerForT(ctx context.Context, t *testing.T, deadlineFunc func(Duty) time.Time, clock clockwork.Clock) Deadliner {
	t.Helper()

	return newDeadliner(ctx, deadlineFunc, clock)
}

// NewDeadliner returns a new instance of Deadline.
//
// It also starts a goroutine which is responsible for reading and storing duties,
// and sending the deadlined duty to receiver's deadlineChan until the context is closed.
func NewDeadliner(ctx context.Context, deadlineFunc func(Duty) time.Time) Deadliner {
	return newDeadliner(ctx, deadlineFunc, clockwork.NewRealClock())
}

// newDeadliner returns a new Deadliner, this is for internal use only.
func newDeadliner(ctx context.Context, deadlineFunc func(Duty) time.Time, clock clockwork.Clock) Deadliner {
	// outputBuffer big enough to support all duty types, which can expire at the same time
	// while external consumer is synchronously adding duties (so not reading output).
	const outputBuffer = 10

	d := &deadliner{
		inputChan:    make(chan deadlineInput), // Not buffering this since writer wait for response.
		deadlineChan: make(chan Duty, outputBuffer),
		clock:        clock,
		quit:         make(chan struct{}),
	}

	go d.run(ctx, deadlineFunc)

	return d
}

func (d *deadliner) run(ctx context.Context, deadlineFunc func(Duty) time.Time) {
	duties := make(map[Duty]bool)
	currDuty, currDeadline := getCurrDuty(duties, deadlineFunc)
	currTimer := d.clock.NewTimer(currDeadline.Sub(d.clock.Now()))

	defer func() {
		close(d.quit)
		currTimer.Stop()
	}()

	setCurrState := func() {
		currTimer.Stop()
		currDuty, currDeadline = getCurrDuty(duties, deadlineFunc)
		currTimer = d.clock.NewTimer(currDeadline.Sub(d.clock.Now()))
	}

	// TODO(dhruv): optimise getCurrDuty and updating current state if earlier deadline detected,
	//  using min heap or ordered map
	for {
		select {
		case <-ctx.Done():
			return
		case input := <-d.inputChan:
			deadline := deadlineFunc(input.duty)
			expired := deadline.Before(d.clock.Now())

			input.success <- !expired

			// Ignore expired duties.
			if expired {
				continue
			}

			duties[input.duty] = true

			if deadline.Before(currDeadline) {
				setCurrState()
			}
		case <-currTimer.Chan():
			// Send deadlined duty to receiver.
			select {
			case <-ctx.Done():
				return
			case d.deadlineChan <- currDuty:
			default:
				log.Warn(ctx, "Deadliner output channel full", nil)
			}

			delete(duties, currDuty)
			setCurrState()
		}
	}
}

// Add adds a duty to be notified of the deadline. It returns true if the duty was added successfully.
func (d *deadliner) Add(duty Duty) bool {
	success := make(chan bool)

	select {
	case <-d.quit:
		return false
	case d.inputChan <- deadlineInput{duty: duty, success: success}:
	}

	select {
	case <-d.quit:
		return false
	case ok := <-success:
		return ok
	}
}

// C returns the deadline channel.
func (d *deadliner) C() <-chan Duty {
	return d.deadlineChan
}

// getCurrDuty gets the duty to process next along-with the duty deadline. It selects duty with the latest deadline.
func getCurrDuty(duties map[Duty]bool, deadlineFunc func(duty Duty) time.Time) (Duty, time.Time) {
	var currDuty Duty
	currDeadline := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	for duty := range duties {
		dutyDeadline := deadlineFunc(duty)
		if currDeadline.After(dutyDeadline) {
			currDuty = duty
			currDeadline = dutyDeadline
		}
	}

	return currDuty, currDeadline
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
