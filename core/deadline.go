// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
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
	marginFactor = 12
)

// DeadlineFunc is a function that returns the deadline for a duty.
type DeadlineFunc func(Duty) (time.Time, bool)

// DeadlineStatus is the result of adding a duty to a Deadliner.
type DeadlineStatus int

const (
	// DeadlineExpired indicates the duty's deadline has already passed,
	// so it was not scheduled and will never be emitted on C().
	DeadlineExpired DeadlineStatus = iota
	// DeadlineScheduled indicates the duty was scheduled for future deadline expiry
	// and will eventually be emitted on C().
	DeadlineScheduled
	// DeadlineExempt indicates the duty type never expires (e.g. exits),
	// so it was not scheduled and will never be emitted on C().
	DeadlineExempt
)

// Deadliner provides duty Deadline functionality. The C method isn’t thread safe and
// may only be used by a single goroutine. So, multiple instances are required
// for different components and use cases.
type Deadliner interface {
	// Add schedules the duty for future deadline expiry and returns DeadlineScheduled.
	// It is idempotent and returns DeadlineScheduled if the duty was previously added and still awaits expiry.
	// It returns DeadlineExpired if the duty's deadline has already passed.
	// It returns DeadlineExempt if the duty type never expires.
	// In the latter two cases the duty is not scheduled and will never be emitted on C().
	Add(duty Duty) DeadlineStatus

	// C returns the same read channel every time and contains deadlined duties.
	// It should only be called by a single goroutine.
	C() <-chan Duty
}

// deadlineInput represents the input to inputChan.
type deadlineInput struct {
	duty    Duty
	success chan<- DeadlineStatus
}

// deadliner implements the Deadliner interface.
type deadliner struct {
	label        string
	inputChan    chan deadlineInput
	deadlineChan chan Duty
	clock        clockwork.Clock
	quit         chan struct{}
}

// NewDeadlinerForT returns a Deadline for use in tests.
func NewDeadlinerForT(ctx context.Context, t *testing.T, deadlineFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	t.Helper()

	return newDeadliner(ctx, "test", deadlineFunc, clock)
}

// NewDeadliner returns a new instance of Deadline.
//
// It also starts a goroutine which is responsible for reading and storing duties,
// and sending the deadlined duty to receiver's deadlineChan until the context is closed.
func NewDeadliner(ctx context.Context, label string, deadlineFunc DeadlineFunc) Deadliner {
	return newDeadliner(ctx, label, deadlineFunc, clockwork.NewRealClock())
}

// NewDutyDeadlineFunc returns the function that provides duty deadlines or false if the duty never deadlines.
func NewDutyDeadlineFunc(ctx context.Context, eth2Cl eth2wrap.Client) (DeadlineFunc, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return nil, err
	}

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
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
		case DutyAttester, DutyAggregator:
			// Attestations and aggregations are kept for a full epoch so late partial signatures are not dropped.
			duration = time.Duration(slotsPerEpoch) * slotDuration
		case DutyPrepareAggregator, DutyPrepareSyncContribution:
			duration = 2 * time.Duration(slotsPerEpoch) * slotDuration
		default:
			duration = slotDuration
		}

		return start.Add(duration + margin), true
	}, nil
}

// newDeadliner returns a new Deadliner, this is for internal use only.
func newDeadliner(ctx context.Context, label string, deadlineFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	// outputBuffer big enough to support all duty types, which can expire at the same time
	// while external consumer is synchronously adding duties (so not reading output).
	const outputBuffer = 10

	d := &deadliner{
		label:        label,
		inputChan:    make(chan deadlineInput), // Not buffering this since writer wait for response.
		deadlineChan: make(chan Duty, outputBuffer),
		clock:        clock,
		quit:         make(chan struct{}),
	}

	go d.run(ctx, deadlineFunc)

	return d
}

func (d *deadliner) run(ctx context.Context, deadlineFunc DeadlineFunc) {
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
			deadline, canExpire := deadlineFunc(input.duty)
			if !canExpire {
				// Drop duties that never expire
				input.success <- DeadlineExempt
				continue
			}

			// Ignore (and signal) duties that have already expired.
			if deadline.Before(d.clock.Now()) {
				input.success <- DeadlineExpired
				continue
			}

			input.success <- DeadlineScheduled

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
				log.Warn(ctx, "Deadliner output channel full", nil,
					z.Str("label", d.label),
					z.Any("duty", currDuty),
				)
			}

			delete(duties, currDuty)
			setCurrState()
		}
	}
}

// Add adds a duty to be notified of the deadline.
// See the Deadliner interface for the meaning of the returned DeadlineStatus.
func (d *deadliner) Add(duty Duty) DeadlineStatus {
	success := make(chan DeadlineStatus)

	select {
	case <-d.quit:
		return DeadlineExpired
	case d.inputChan <- deadlineInput{duty: duty, success: success}:
	}

	select {
	case <-d.quit:
		return DeadlineExpired
	case status := <-success:
		return status
	}
}

// C returns the deadline channel.
func (d *deadliner) C() <-chan Duty {
	return d.deadlineChan
}

// getCurrDuty gets the duty to process next along-with the duty deadline. It selects duty with the latest deadline.
func getCurrDuty(duties map[Duty]bool, deadlineFunc DeadlineFunc) (Duty, time.Time) {
	var currDuty Duty

	currDeadline := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	for duty := range duties {
		dutyDeadline, ok := deadlineFunc(duty)
		if !ok {
			// Ignore the duties that never expire.
			continue
		}

		if currDeadline.After(dutyDeadline) {
			currDuty = duty
			currDeadline = dutyDeadline
		}
	}

	return currDuty, currDeadline
}
