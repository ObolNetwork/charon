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

// Deadliner provides duty Deadline functionality. The C method isn’t thread safe and may only be used by a single goroutine.So, multiple
// instances are required for different components and use cases.
type Deadliner interface {
	// Add adds a duty to be notified of the Deadline via C. Note that duties will be deduplicated and only a single duty will be provided via C.
	Add(duty Duty)

	// C returns the same read channel every time and contains deadlined duties.
	// It should only be called by a single goroutine.
	C() <-chan Duty
}

// Deadline implements the Deadliner interface.
type Deadline struct {
	mu sync.Mutex

	eth2Cl slotTimeProvider

	dutyChan     chan Duty
	deadlineChan chan Duty

	// duties represents a set since duty deduplication is required.
	duties map[Duty]bool

	// deadlineFunc returns deadline for the given duty.
	deadlineFunc func(Duty) time.Time
}

// NewDeadliner returns a new instance of Deadline.
func NewDeadliner(ctx context.Context, eth2Svc eth2client.Service) (*Deadline, error) {
	d, err := NewDutyDeadlineFunc(ctx, eth2Svc)
	if err != nil {
		return nil, err
	}

	deadliner := &Deadline{
		eth2Cl:       eth2Svc.(slotTimeProvider),
		dutyChan:     make(chan Duty),
		deadlineChan: make(chan Duty),
		duties:       make(map[Duty]bool),
		deadlineFunc: d,
	}

	go func() {
		// The following are the responsibilities of this go routine:
		// 1. Store the duty got from consumer calling Add method in dutyChan, to make sure only this go routine
		// is responsible for updating duties map.
		// 2. Calculate min duty from the map
		// 3. send the duty to consumer when deadline comes in deadlineChan
	}()

	return deadliner, nil
}

// Add adds a duty to be notified of the deadline.
func (d *Deadline) Add(duty Duty) {
	d.dutyChan <- duty
}

// deleteDuty deletes a duty whose notification has been already processed.
func (d *Deadline) deleteDuty(duty Duty) {
	delete(d.duties, duty)
}

// getMinDuty gets the first duty to process.
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

// C returns the deadline channel.
func (d *Deadline) C() <-chan Duty {
	return d.deadlineChan
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
