// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

//go:generate mockery --name=Deadliner --output=mocks --outpkg=mocks --case=underscore

const (
	// marginFactor defines the fraction of the slot duration to use as a margin.
	// This is to consider network delays and other factors that may affect the timing.
	marginFactor      = 12
	expiredBufferSize = 10
	tickerInterval    = time.Second
)

// DeadlineFunc is a function that returns the deadline for a duty.
type DeadlineFunc func(Duty) (time.Time, bool)

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

// deadliner implements the Deadliner interface.
type deadliner struct {
	lock         sync.Mutex
	label        string
	deadlineFunc DeadlineFunc
	duties       map[Duty]time.Time
	expiredChan  chan Duty
	clock        clockwork.Clock
	done         chan struct{}
}

// NewDeadlinerForT returns a Deadline for use in tests.
func NewDeadlinerForT(ctx context.Context, t *testing.T, deadlineFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	t.Helper()

	return newDeadliner(ctx, "test", deadlineFunc, clock)
}

// NewDeadliner returns a new instance of Deadline.
//
// It also starts a goroutine which is responsible for reading and storing duties,
// and sending the deadlined duty to receiver's expiredChan until the context is closed.
func NewDeadliner(ctx context.Context, label string, deadlineFunc DeadlineFunc) Deadliner {
	return newDeadliner(ctx, label, deadlineFunc, clockwork.NewRealClock())
}

// NewDutyDeadlineFunc returns the function that provides duty deadlines or false if the duty never deadlines.
func NewDutyDeadlineFunc(ctx context.Context, eth2Cl eth2wrap.Client) (DeadlineFunc, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	slotDuration, _, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	return func(duty Duty) (time.Time, bool) {
		switch duty.Type {
		case DutyExit, DutyBuilderRegistration:
			// Do not timeout exit or registration duties.
			return time.Time{}, false
		default:
		}

		var (
			start    = genesisTime.Add(slotDuration * time.Duration(duty.Slot))
			margin   = slotDuration / marginFactor
			duration time.Duration
		)

		switch duty.Type {
		case DutyProposer, DutyRandao:
			duration = slotDuration / 3
		case DutySyncMessage:
			duration = 2 * slotDuration / 3
		case DutyAttester, DutyAggregator, DutyPrepareAggregator:
			// Even though attestations and aggregations are acceptable even after 2 slots, the rewards are heavily diminished.
			duration = 2 * slotDuration
		default:
			duration = slotDuration
		}

		return start.Add(duration + margin), true
	}, nil
}

// newDeadliner returns a new Deadliner, this is for internal use only.
func newDeadliner(ctx context.Context, label string, deadlineFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	d := &deadliner{
		label:        label,
		deadlineFunc: deadlineFunc,
		duties:       make(map[Duty]time.Time),
		expiredChan:  make(chan Duty, expiredBufferSize),
		clock:        clock,
		done:         make(chan struct{}),
	}

	go d.run(ctx)

	return d
}

func (d *deadliner) run(ctx context.Context) {
	defer close(d.done)

	// The simple approach does not require a min-heap or priority queue to store the duties and their deadlines,
	// but it is sufficient for our use case as the number of duties is expected to be small.
	// A disadvantage of this approach is the expiration precision is rounded to the nearest second.
	timer := d.clock.NewTicker(tickerInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.Chan():
			// Get all expired duties at the current time.
			expiredDuties := d.getExpiredDuties(d.clock.Now())
			if len(expiredDuties) == 0 {
				continue
			}

			log.Debug(ctx, "Deadliner.run() got expired duties", z.Int("count", len(expiredDuties)))

			for _, expiredDuty := range expiredDuties {
				// Send the expired duty to the receiver.
				select {
				case <-ctx.Done():
					return
				case d.expiredChan <- expiredDuty:
				}
			}
		}
	}
}

// Add adds a duty to be notified of the deadline. It returns true if the duty was added successfully.
func (d *deadliner) Add(duty Duty) bool {
	log.Debug(context.Background(), "Deadliner.Add()", z.Any("duty", duty))

	select {
	case <-d.done:
		// Run goroutine has stopped, ignore new duties.
		return false
	default:
	}

	deadline, canExpire := d.deadlineFunc(duty)
	if !canExpire {
		// Drop duties that never expire
		return false
	}

	expired := deadline.Before(d.clock.Now())
	if expired {
		// Drop expired duties
		return false
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	d.duties[duty] = deadline

	return true
}

// C returns the deadline channel.
func (d *deadliner) C() <-chan Duty {
	return d.expiredChan
}

// getExpiredDuties selects all expired duties.
func (d *deadliner) getExpiredDuties(now time.Time) []Duty {
	expiredDuties := []Duty{}

	d.lock.Lock()
	defer d.lock.Unlock()

	for duty, deadline := range d.duties {
		if deadline.Before(now) {
			expiredDuties = append(expiredDuties, duty)
			delete(d.duties, duty)
		}
	}

	return expiredDuties
}
