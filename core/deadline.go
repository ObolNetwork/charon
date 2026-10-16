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

// DeadlineFunc returns the time at which a duty expires, or false if it never does: by when it is
// submitted, see NewDutyDeadlineFunc, or until when its data is retained, see NewDutyRetentionFunc.
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

// Deadliner tracks duties until they expire, at the time the expiry function it is created with
// provides, their submission deadline or their retention, and emits them then. The C method isn’t
// thread safe and may only be used by a single goroutine. So, multiple instances are required
// for different components and use cases.
type Deadliner interface {
	// Add schedules the duty for future deadline expiry and returns DeadlineScheduled.
	// It is idempotent and returns DeadlineScheduled if the duty was previously added and still awaits expiry.
	// It returns DeadlineExpired if the duty's deadline has already passed.
	// It returns DeadlineExempt if the duty type never expires.
	// In the latter two cases the duty is not scheduled and will never be emitted on C().
	Add(duty Duty) DeadlineStatus

	// C returns the same read channel every time and contains expired duties.
	// It should only be called by a single goroutine.
	C() <-chan Duty
}

// expiryInput represents the input to inputChan.
type expiryInput struct {
	duty    Duty
	success chan<- DeadlineStatus
}

// deadliner implements the Deadliner interface.
type deadliner struct {
	label      string
	inputChan  chan expiryInput
	expiryChan chan Duty
	clock      clockwork.Clock
	quit       chan struct{}
}

// NewDeadlinerForT returns a Deadliner for use in tests.
func NewDeadlinerForT(ctx context.Context, t *testing.T, expiryFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	t.Helper()

	return newDeadliner(ctx, "test", expiryFunc, clock)
}

// NewDeadliner returns a new Deadliner expiring duties at the time the expiry function provides.
//
// It also starts a goroutine which is responsible for reading and storing duties,
// and sending the expired duty to receiver's expiryChan until the context is closed.
func NewDeadliner(ctx context.Context, label string, expiryFunc DeadlineFunc) Deadliner {
	return newDeadliner(ctx, label, expiryFunc, clockwork.NewRealClock())
}

// NewDutyDeadlineFunc returns the function that provides the deadlines by which duties are
// submitted, or false if the duty never deadlines: until then the cluster spends on producing the
// duty. Deadlines derived from gloas slot offsets follow the fork schedule at runtime.
func NewDutyDeadlineFunc(ctx context.Context, eth2Cl eth2wrap.Client, forkSchedule func() eth2wrap.ForkForkSchedule) (DeadlineFunc, error) {
	timing, err := newDutyTiming(ctx, eth2Cl, forkSchedule)
	if err != nil {
		return nil, err
	}

	return timing.expiryFunc(timing.deadline), nil
}

// NewDutyRetentionFunc returns the function that provides the deadlines until which the data of
// duties is retained for other components, or false if it is retained forever. It is the
// submission deadline of NewDutyDeadlineFunc, except for proposals, which are retained until the
// end of the slot to serve the reveal of their execution payload envelope.
func NewDutyRetentionFunc(ctx context.Context, eth2Cl eth2wrap.Client, forkSchedule func() eth2wrap.ForkForkSchedule) (DeadlineFunc, error) {
	timing, err := newDutyTiming(ctx, eth2Cl, forkSchedule)
	if err != nil {
		return nil, err
	}

	return timing.expiryFunc(timing.retention), nil
}

// dutyTiming derives the deadlines of duties from the slot timing of the network.
type dutyTiming struct {
	genesisTime   time.Time
	slotDuration  time.Duration
	slotsPerEpoch uint64
	slotOffset    SlotOffsetFunc
}

// newDutyTiming returns the slot timing of the network fetched from the beacon node.
func newDutyTiming(ctx context.Context, eth2Cl eth2wrap.Client, forkSchedule func() eth2wrap.ForkForkSchedule) (dutyTiming, error) {
	genesisTime, err := eth2wrap.FetchGenesisTime(ctx, eth2Cl)
	if err != nil {
		return dutyTiming{}, err
	}

	slotDuration, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return dutyTiming{}, err
	}

	timing, err := eth2wrap.FetchSlotTimingConfig(ctx, eth2Cl)
	if err != nil {
		return dutyTiming{}, err
	}

	return dutyTiming{
		genesisTime:   genesisTime,
		slotDuration:  slotDuration,
		slotsPerEpoch: slotsPerEpoch,
		slotOffset:    newSlotOffsetFunc(slotDuration, slotsPerEpoch, timing, forkSchedule),
	}, nil
}

// expiryFunc returns the function providing when duties expire, by submission deadline or
// retention: the duration the duration function provides after the start of their slot, plus a
// margin for network delays, or false if the duty never expires.
func (t dutyTiming) expiryFunc(durationFunc func(Duty) (time.Duration, bool)) DeadlineFunc {
	return func(duty Duty) (time.Time, bool) {
		duration, ok := durationFunc(duty)
		if !ok {
			return time.Time{}, false
		}

		start := t.genesisTime.Add(t.slotDuration * time.Duration(duty.Slot))
		margin := t.slotDuration / marginFactor

		return start.Add(duration + margin), true
	}
}

// deadline returns how long after the start of its slot the duty is submitted by, or false if it
// never deadlines.
func (t dutyTiming) deadline(duty Duty) (time.Duration, bool) {
	//nolint: revive // prioritise clarity
	switch duty.Type {
	case DutyExit, DutyBuilderRegistration:
		// Do not timeout exit or registration duties.
		return 0, false
	case DutyProposer, DutyRandao:
		// A proposal's useful life ends once attesters vote at the attestation due offset,
		// a third of the slot pre-gloas and a quarter from the gloas fork onwards.
		return t.slotOffset(Duty{Slot: duty.Slot, Type: DutyAttester}), true
	case DutySyncMessage, DutySyncContribution:
		return t.slotDuration, true
	case DutyAttester, DutyAggregator:
		// Attestations and aggregations are kept for a full epoch so late partial signatures are not dropped.
		return time.Duration(t.slotsPerEpoch) * t.slotDuration, true
	case DutyPrepareAggregator, DutyPrepareSyncContribution:
		return 2 * time.Duration(t.slotsPerEpoch) * t.slotDuration, true
	case DutyPayloadAttestation:
		// Payload attestation messages are only accepted on gossip within their own slot.
		return t.slotDuration, true
	case DutyProposerPreferences:
		// Preferences are submitted from the start of the epoch before the proposal epoch
		// (the earliest the assignment is derivable) and are keyed by the proposal slot,
		// so entries live from submission (up to ~2 epochs early) until the slot passes.
		return t.slotDuration, true
	case DutyExecutionPayloadEnvelope:
		// The payload envelope is revealed within the proposal slot itself, after the block
		// it commits to and before the payload timeliness committee deadline.
		return t.slotDuration, true
	default:
		return t.slotDuration, true
	}
}

// retention returns how long after the start of its slot the duty's data is retained for other
// components, or false if it is retained forever.
func (t dutyTiming) retention(duty Duty) (time.Duration, bool) {
	switch duty.Type {
	case DutyProposer:
		// An agreed proposal is retained until the end of the slot, past its submission deadline
		// at the attestation due offset: from gloas the execution payload envelope of a self-built
		// block is revealed after the block, from the agreed block and its payload contents.
		return t.slotDuration, true
	default:
		return t.deadline(duty)
	}
}

// newDeadliner returns a new Deadliner, this is for internal use only.
func newDeadliner(ctx context.Context, label string, expiryFunc DeadlineFunc, clock clockwork.Clock) Deadliner {
	// outputBuffer big enough to support all duty types, which can expire at the same time
	// while external consumer is synchronously adding duties (so not reading output).
	const outputBuffer = 10

	d := &deadliner{
		label:      label,
		inputChan:  make(chan expiryInput), // Not buffering this since writer wait for response.
		expiryChan: make(chan Duty, outputBuffer),
		clock:      clock,
		quit:       make(chan struct{}),
	}

	go d.run(ctx, expiryFunc)

	return d
}

func (d *deadliner) run(ctx context.Context, expiryFunc DeadlineFunc) {
	duties := make(map[Duty]bool)
	currDuty, currExpiry := getCurrDuty(duties, expiryFunc)
	currTimer := d.clock.NewTimer(currExpiry.Sub(d.clock.Now()))

	defer func() {
		close(d.quit)
		currTimer.Stop()
	}()

	setCurrState := func() {
		currTimer.Stop()

		currDuty, currExpiry = getCurrDuty(duties, expiryFunc)
		currTimer = d.clock.NewTimer(currExpiry.Sub(d.clock.Now()))
	}

	// TODO(dhruv): optimise getCurrDuty and updating current state if earlier expiry detected,
	//  using min heap or ordered map
	for {
		select {
		case <-ctx.Done():
			return
		case input := <-d.inputChan:
			expiry, canExpire := expiryFunc(input.duty)
			if !canExpire {
				// Drop duties that never expire
				input.success <- DeadlineExempt
				continue
			}

			// Ignore (and signal) duties that have already expired.
			if expiry.Before(d.clock.Now()) {
				input.success <- DeadlineExpired
				continue
			}

			input.success <- DeadlineScheduled

			duties[input.duty] = true

			if expiry.Before(currExpiry) {
				setCurrState()
			}
		case <-currTimer.Chan():
			// Send expired duty to receiver.
			select {
			case <-ctx.Done():
				return
			case d.expiryChan <- currDuty:
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
	case d.inputChan <- expiryInput{duty: duty, success: success}:
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
	return d.expiryChan
}

// getCurrDuty gets the duty to process next along-with the duty deadline. It selects duty with the latest deadline.
func getCurrDuty(duties map[Duty]bool, expiryFunc DeadlineFunc) (Duty, time.Time) {
	var currDuty Duty

	currExpiry := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	for duty := range duties {
		dutyExpiry, ok := expiryFunc(duty)
		if !ok {
			// Ignore the duties that never expire.
			continue
		}

		if currExpiry.After(dutyExpiry) {
			currDuty = duty
			currExpiry = dutyExpiry
		}
	}

	return currDuty, currExpiry
}
