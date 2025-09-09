// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package qbft is an implementation of the https://arxiv.org/pdf/2002.03613.pdf paper
// referenced by the QBFT spec https://github.com/ConsenSys/qbft-formal-spec-and-verification.
package qbft

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

// Transport abstracts the transport layer between processes in the consensus system.
type Transport[I any, V comparable] struct {
	// Broadcast sends a message with the provided fields to all other
	// processes in the system (including this process).
	//
	// Note that a non-nil error exits the algorithm.
	Broadcast func(ctx context.Context, typ MsgType, instance I, source int64, round int64, value V, pr int64, pv V, justification []Msg[I, V]) error

	// Receive returns a stream of messages received
	// from other processes in the system (including this process).
	Receive <-chan Msg[I, V]
}

// Definition defines the consensus system parameters that are external to the qbft algorithm.
// This remains constant across multiple instances of consensus (calls to Run).
type Definition[I any, V comparable, C any] struct {
	// IsLeader is a deterministic leader election function.
	IsLeader func(instance I, round, process int64) bool
	// NewTimer returns a new timer channel and stop function for the round.
	NewTimer func(round int64) (<-chan time.Time, func())
	// Compare is called when leader proposes value and we compare it with our local value.
	Compare func(ctx context.Context, qcommit Msg[I, V], inputValueReceivedCh chan struct{}, inputValueSource C) error
	// Decide is called when consensus has been reached on a value.
	Decide func(ctx context.Context, instance I, value V, qcommit []Msg[I, V])
	// LogUponRule allows debug logging of triggered upon rules on message receipt.
	LogUponRule func(ctx context.Context, instance I, process, round int64, msg Msg[I, V], uponRule UponRule)
	// LogRoundChange allows debug logging of round changes.
	// It includes the rule that triggered it and all received round messages.
	LogRoundChange func(ctx context.Context, instance I, process, round, newRound int64, uponRule UponRule, msgs []Msg[I, V])
	// LogUnjust allows debug logging of unjust messages.
	LogUnjust func(ctx context.Context, instance I, process int64, msg Msg[I, V])

	// Nodes is the total number of nodes/processes participating in consensus.
	Nodes int
	// FIFOLimit limits the amount of message buffered for each peer.
	FIFOLimit int
}

// Quorum returns the quorum count for the system.
// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
func (d Definition[I, V, C]) Quorum() int {
	return int(math.Ceil(float64(d.Nodes*2) / 3))
}

// Faulty returns the maximum number of faulty/byzantium nodes supported in the system.
// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
func (d Definition[I, V, C]) Faulty() int {
	return int(math.Floor(float64(d.Nodes-1) / 3))
}

//go:generate stringer -type=MsgType

// MsgType defines the QBFT message types.
type MsgType int64

// Note that message type ordering MUST not change, since it breaks backwards compatibility.
const (
	MsgUnknown     MsgType = 0
	MsgPrePrepare  MsgType = 1
	MsgPrepare     MsgType = 2
	MsgCommit      MsgType = 3
	MsgRoundChange MsgType = 4
	MsgDecided     MsgType = 5
	msgSentinel    MsgType = 6
)

func (t MsgType) Valid() bool {
	return t > MsgUnknown && t < msgSentinel
}

func (t MsgType) String() string {
	return typeLabels[t]
}

var typeLabels = map[MsgType]string{
	MsgUnknown:     "unknown",
	MsgPrePrepare:  "pre_prepare",
	MsgPrepare:     "prepare",
	MsgCommit:      "commit",
	MsgRoundChange: "round_change",
	MsgDecided:     "decided",
}

// Msg defines the inter process messages.
type Msg[I any, V comparable] interface {
	// Type of the message.
	Type() MsgType
	// Instance identifies the consensus instance.
	Instance() I
	// Source identifies the process that sent the message.
	Source() int64
	// Round the message pertains to.
	Round() int64
	// Value being proposed, usually a hash.
	Value() V
	// ValueSource being proposed.
	ValueSource() (*anypb.Any, error)
	// PreparedRound is the justified prepared round.
	PreparedRound() int64
	// PreparedValue is the justified prepared value.
	PreparedValue() V
	// Justification is the set of messages that explicitly justifies this message.
	Justification() []Msg[I, V]
}

// UponRule defines the event based rules that are triggered when messages are received.
type UponRule int64

func (r UponRule) String() string {
	return ruleLabels[r]
}

const (
	UponNothing UponRule = iota
	UponJustifiedPrePrepare
	UponQuorumPrepares
	UponQuorumCommits
	UponUnjustQuorumRoundChanges
	UponFPlus1RoundChanges
	UponQuorumRoundChanges
	UponJustifiedDecided
	UponRoundTimeout // This is not triggered by a message, but by a timer.
)

var ruleLabels = map[UponRule]string{
	UponNothing:                  "nothing",
	UponJustifiedPrePrepare:      "justified_pre_prepare",
	UponQuorumPrepares:           "quorum_prepares",
	UponQuorumCommits:            "quorum_commits",
	UponUnjustQuorumRoundChanges: "unjust_quorum_round_changes",
	UponFPlus1RoundChanges:       "f_plus_1_round_changes",
	UponQuorumRoundChanges:       "quorum_round_changes",
	UponJustifiedDecided:         "justified_decided",
	UponRoundTimeout:             "round_timeout",
}

// dedupKey defines the key used to deduplicate upon rules.
type dedupKey struct {
	UponRule UponRule
	Round    int64
}

// InputValue is a convenience function to create a populated input value channel.
func InputValue[V comparable](inputValue V) <-chan V {
	ch := make(chan V, 1)
	ch <- inputValue

	return ch
}

// InputValueSource is a convenience function to create a populated input value source channel.
func InputValueSource[C any](inputValueSource C) <-chan C {
	ch := make(chan C, 1)
	ch <- inputValueSource

	return ch
}

// Run executes the consensus algorithm until the context closed.
// The generic type I is the instance of consensus and can be anything.
// The generic type V is the arbitrary data value being proposed; it only requires an Equal method.
// The generic type C is the compare value, used to compare leader's proposed value with local value and can be anything.
func Run[I any, V comparable, C any](ctx context.Context, d Definition[I, V, C], t Transport[I, V], instance I, process int64, inputValueCh <-chan V, inputValueSourceCh <-chan C) (err error) {
	defer func() {
		// Panics are used for assertions and sanity checks to reduce lines of code
		// and to improve readability. Catch them here.
		if r := recover(); r != nil {
			if !strings.Contains(fmt.Sprint(r), "bug") {
				panic(r) // Only catch internal sanity checks.
			}

			err = fmt.Errorf("qbft sanity check: %v", r) //nolint: forbidigo // Wrapping a panic, not error.
		}
	}()

	// === State ===

	var (
		round                 int64 = 1
		inputValue            V
		inputValueSource      C
		ppjCache              []Msg[I, V] // Cached pre-prepare justification for the current round (nil value is unset).
		inputValueReceivedCh  = make(chan struct{}, 1)
		preparedRound         int64
		preparedValue         V
		preparedJustification []Msg[I, V]
		qCommit               []Msg[I, V]
		buffer                = make(map[int64][]Msg[I, V])
		dedupRules            = make(map[dedupKey]bool)
		timerChan             <-chan time.Time
		stopTimer             func()
	)

	// === Helpers ==

	// broadcastMsg broadcasts a non-ROUND-CHANGE message for current round.
	broadcastMsg := func(typ MsgType, value V, justification []Msg[I, V]) error {
		return t.Broadcast(ctx, typ, instance, process, round,
			value, 0, zeroVal[V](), justification)
	}

	// broadcastRoundChange broadcasts a ROUND-CHANGE message with current state.
	broadcastRoundChange := func() error {
		return t.Broadcast(ctx, MsgRoundChange, instance, process, round,
			zeroVal[V](), preparedRound, preparedValue, preparedJustification)
	}

	// broadcastOwnPrePrepare broadcasts a PRE-PREPARE message with current state
	// and our own input value if present, otherwise it caches the justification
	// to be used when the input value becomes available.
	broadcastOwnPrePrepare := func(justification []Msg[I, V]) error {
		if justification == nil {
			panic("bug: justification must not be nil")
		} else if ppjCache != nil {
			panic("bug: justification cache must be nil")
		}

		if isZeroVal(inputValue) {
			// Can't broadcast a pre-prepare yet, need to wait for an input value.
			ppjCache = justification
			return nil
		}

		return broadcastMsg(MsgPrePrepare, inputValue, justification)
	}

	// bufferMsg adds the message to each process' FIFO queue.
	bufferMsg := func(msg Msg[I, V]) {
		fifo := buffer[msg.Source()]

		fifo = append(fifo, msg)
		if len(fifo) > d.FIFOLimit {
			fifo = fifo[len(fifo)-d.FIFOLimit:]
		}

		buffer[msg.Source()] = fifo
	}

	// isDuplicatedRule returns true if the rule has been already executed since last round change.
	isDuplicatedRule := func(rule UponRule, msgRound int64) bool {
		key := dedupKey{UponRule: rule, Round: msgRound}

		if !dedupRules[key] {
			dedupRules[key] = true

			return false
		}

		return true
	}

	// changeRound updates round and clears the rule dedup state.
	changeRound := func(newRound int64, rule UponRule) {
		if round == newRound {
			return
		}

		d.LogRoundChange(ctx, instance, process, round, newRound, rule, extractRoundMsgs(buffer, round))
		round = newRound
		dedupRules = make(map[dedupKey]bool)
		ppjCache = nil
	}

	// === Algorithm ===

	{ // Algorithm 1:11
		if d.IsLeader(instance, round, process) { // Note round==1 at this point.
			err := broadcastOwnPrePrepare([]Msg[I, V]{}) // Empty justification since round==1
			if err != nil {
				return err
			}
		}

		timerChan, stopTimer = d.NewTimer(round)
	}

	// Handle events until cancelled.
	for {
		var err error

		select {
		case inputValue = <-inputValueCh:
			if isZeroVal(inputValue) {
				return errors.New("zero input value not supported")
			}

			if ppjCache != nil {
				// Broadcast the pre-prepare now that we have a input value using the cached justification.
				err = broadcastMsg(MsgPrePrepare, inputValue, ppjCache)
			}

			inputValueCh = nil // Don't read from this channel again.

		case inputValueSource = <-inputValueSourceCh:
			inputValueSourceCh = nil // Don't read from this channel again.

			inputValueReceivedCh <- struct{}{}

		case msg := <-t.Receive:
			// Just send Qcommit if consensus already decided
			if len(qCommit) > 0 {
				if msg.Source() != process && msg.Type() == MsgRoundChange { // Algorithm 3:17
					err = broadcastMsg(MsgDecided, qCommit[0].Value(), qCommit)
				}

				break
			}

			if !isJustified(d, instance, msg) { // Drop unjust messages
				d.LogUnjust(ctx, instance, process, msg)
				break
			}

			bufferMsg(msg)

			rule, justification := classify(d, instance, round, process, buffer, msg)
			if rule == UponNothing || isDuplicatedRule(rule, msg.Round()) {
				// Do nothing more if no rule or duplicate rule was triggered
				break
			}

			d.LogUponRule(ctx, instance, process, round, msg, rule)

			switch rule {
			case UponJustifiedPrePrepare: // Algorithm 2:1
				// Applicable to current or future rounds (since justified)
				changeRound(msg.Round(), rule)

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				err = broadcastMsg(MsgPrepare, msg.Value(), nil)

			case UponQuorumPrepares: // Algorithm 2:4
				// Only applicable to current round
				preparedRound = round /* == msg.Round*/
				preparedValue = msg.Value()

				errCompare := d.Compare(ctx, msg, inputValueReceivedCh, inputValueSource)
				if errCompare != nil {
					log.Warn(ctx, "Compare leader value with local value failed", errCompare)
					continue
				}

				preparedJustification = justification

				err = broadcastMsg(MsgCommit, preparedValue, nil)

			case UponQuorumCommits, UponJustifiedDecided: // Algorithm 2:8
				// Applicable to any round (since can be justified)
				changeRound(msg.Round(), rule)

				qCommit = justification

				stopTimer()

				timerChan = nil

				d.Decide(ctx, instance, msg.Value(), justification)

			case UponFPlus1RoundChanges: // Algorithm 3:5
				// Only applicable to future rounds
				changeRound(nextMinRound(d, justification, round /* < msg.Round */), rule)

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				err = broadcastRoundChange()

			case UponQuorumRoundChanges: // Algorithm 3:11
				// Only applicable to current round (round > 1)
				if _, pv, ok := getSingleJustifiedPrPv(d, justification); ok {
					// Send pre-prepare using prepared value (not our own input value)
					err = broadcastMsg(MsgPrePrepare, pv, justification)
				} else {
					// Send pre-prepare using our own input value
					err = broadcastOwnPrePrepare(justification)
				}
			case UponUnjustQuorumRoundChanges:
				// Ignore bug or byzantine

			default:
				panic("bug: invalid rule")
			}

		case <-timerChan: // Algorithm 3:1
			changeRound(round+1, UponRoundTimeout)

			stopTimer()
			timerChan, stopTimer = d.NewTimer(round)

			err = broadcastRoundChange()

		case <-ctx.Done(): // Cancelled
			return ctx.Err()
		}

		if err != nil { // Errors are considered fatal.
			return err
		}
	}
}

// extractRoundMsgs returns all messages from the provided round.
func extractRoundMsgs[I any, V comparable](buffer map[int64][]Msg[I, V], round int64) []Msg[I, V] {
	var resp []Msg[I, V]

	for _, msgs := range buffer {
		for _, msg := range msgs {
			if msg.Round() == round {
				resp = append(resp, msg)
			}
		}
	}

	return resp
}

// classify returns the rule triggered upon receipt of the last message and its justifications.
func classify[I any, V comparable, C any](d Definition[I, V, C], instance I, round, process int64, buffer map[int64][]Msg[I, V], msg Msg[I, V]) (UponRule, []Msg[I, V]) {
	switch msg.Type() {
	case MsgDecided:
		return UponJustifiedDecided, msg.Justification()

	case MsgPrePrepare:
		// Only ignore old rounds, since PRE-PREPARE is justified we may jump ahead.
		if msg.Round() < round {
			return UponNothing, nil
		}

		return UponJustifiedPrePrepare, nil

	case MsgPrepare:
		// Ignore other rounds, since PREPARE isn't justified.
		if msg.Round() != round {
			return UponNothing, nil
		}

		prepares := filterByRoundAndValue(flatten(buffer), MsgPrepare, msg.Round(), msg.Value())
		if len(prepares) >= d.Quorum() {
			return UponQuorumPrepares, prepares
		}

	case MsgCommit:
		// Ignore other rounds, since COMMIT isn't justified.
		if msg.Round() != round {
			return UponNothing, nil
		}

		commits := filterByRoundAndValue(flatten(buffer), MsgCommit, msg.Round(), msg.Value())
		if len(commits) >= d.Quorum() {
			return UponQuorumCommits, commits
		}

	case MsgRoundChange:
		// Only ignore old rounds.
		if msg.Round() < round {
			return UponNothing, nil
		}

		all := flatten(buffer)

		if msg.Round() > round {
			// Jump ahead if we received F+1 higher ROUND-CHANGEs.
			if frc, ok := getFPlus1RoundChanges(d, all, round); ok {
				return UponFPlus1RoundChanges, frc
			}

			return UponNothing, nil
		}

		/* else msg.Round == round */

		if qrc := filterRoundChange(all, msg.Round()); len(qrc) < d.Quorum() {
			return UponNothing, nil
		}

		qrc, ok := getJustifiedQrc(d, all, msg.Round())
		if !ok {
			return UponUnjustQuorumRoundChanges, nil
		}

		if !d.IsLeader(instance, msg.Round(), process) {
			return UponNothing, nil
		}

		return UponQuorumRoundChanges, qrc

	default:
		panic("bug: invalid type")
	}

	return UponNothing, nil
}

// nextMinRound implements algorithm 3:6 and returns the next minimum round
// from received round change messages.
func nextMinRound[I any, V comparable, C any](d Definition[I, V, C], frc []Msg[I, V], round int64) int64 {
	// Get all RoundChange messages with round (rj) higher than current round (ri)
	if len(frc) < d.Faulty()+1 {
		panic("bug: Frc too short")
	}

	// Get the smallest round in the set.
	rmin := int64(math.MaxInt64)

	for _, msg := range frc {
		if msg.Type() != MsgRoundChange {
			panic("bug: Frc contain non-round change")
		} else if msg.Round() <= round {
			panic("bug: Frc round not in future")
		}

		if rmin > msg.Round() {
			rmin = msg.Round()
		}
	}

	return rmin
}

// isJustified returns true if message is justified or if it does not need justification.
func isJustified[I any, V comparable, C any](d Definition[I, V, C], instance I, msg Msg[I, V]) bool {
	//nolint:revive // `case MsgPrepare` and `case MsgCommit` having same result is not an issue, it improves readability.
	switch msg.Type() {
	case MsgPrePrepare:
		return isJustifiedPrePrepare(d, instance, msg)
	case MsgPrepare:
		return true
	case MsgCommit:
		return true
	case MsgRoundChange:
		return isJustifiedRoundChange(d, msg)
	case MsgDecided:
		return isJustifiedDecided(d, msg)
	default:
		panic("bug: invalid message type")
	}
}

// isJustifiedRoundChange returns true if the ROUND_CHANGE message's
// prepared round and value is justified.
func isJustifiedRoundChange[I any, V comparable, C any](d Definition[I, V, C], msg Msg[I, V]) bool {
	if msg.Type() != MsgRoundChange {
		panic("bug: not a round change message")
	}

	// ROUND-CHANGE justification contains quorum PREPARE messages that justifies Pr and Pv.
	prepares := msg.Justification()
	pr := msg.PreparedRound()
	pv := msg.PreparedValue()

	if len(prepares) == 0 {
		// If no justification, ensure null prepared round and value.
		// return pr == 0 && isZeroVal(pv)
		return true
	}

	// No need to check for all possible combinations, since justified should only contain a one.

	if len(prepares) < d.Quorum() {
		return false
	}

	uniq := uniqSource[I, V]()
	for _, prepare := range prepares {
		if !uniq(prepare) {
			return false
		}

		if prepare.Type() != MsgPrepare {
			return false
		}

		if prepare.Round() != pr {
			return false
		}

		if prepare.Value() != pv {
			return false
		}
	}

	return true
}

// isJustifiedDecided returns true if the decided message is justified by quorum COMMIT messages
// of identical round and value.
func isJustifiedDecided[I any, V comparable, C any](d Definition[I, V, C], msg Msg[I, V]) bool {
	if msg.Type() != MsgDecided {
		panic("bug: not a decided message")
	}

	v := msg.Value()
	commits := filterMsgs(msg.Justification(), MsgCommit, msg.Round(), &v, nil, nil)

	return len(commits) >= d.Quorum()
}

// isJustifiedPrePrepare returns true if the PRE-PREPARE message is justified.
func isJustifiedPrePrepare[I any, V comparable, C any](d Definition[I, V, C], instance I, msg Msg[I, V]) bool {
	if msg.Type() != MsgPrePrepare {
		panic("bug: not a preprepare message")
	}

	if !d.IsLeader(instance, msg.Round(), msg.Source()) {
		return false
	}

	if msg.Round() == 1 {
		return true
	}

	pv, ok := containsJustifiedQrc(d, msg.Justification(), msg.Round())
	if !ok {
		return false
	}

	if isZeroVal(pv) {
		return true // New value being proposed
	}

	return msg.Value() == pv // Ensure Pv is being proposed
}

// containsJustifiedQrc implements algorithm 4:1 and returns true and pv if
// the messages contains a justified quorum ROUND_CHANGEs (Qrc).
func containsJustifiedQrc[I any, V comparable, C any](d Definition[I, V, C], justification []Msg[I, V], round int64) (V, bool) {
	qrc := filterRoundChange(justification, round)
	if len(qrc) < d.Quorum() {
		return zeroVal[V](), false
	}

	// No need to calculate J1 or J2 for all possible combinations,
	// since justification should only contain one.

	// J1: If qrc contains quorum ROUND-CHANGEs with null pv and null pr.
	allNull := true

	for _, rc := range qrc {
		if rc.PreparedRound() != 0 || !isZeroVal(rc.PreparedValue()) {
			allNull = false
			break
		}
	}

	if allNull {
		return zeroVal[V](), true
	}

	// J2: if the justification has a quorum of valid PREPARE messages
	// with pr and pv equaled to highest pr and pv in Qrc (other than null).

	// Get pr and pv from quorum PREPARES
	pr, pv, ok := getSingleJustifiedPrPv(d, justification)
	if !ok {
		return zeroVal[V](), false
	}

	var found bool

	for _, rc := range qrc {
		// Ensure no ROUND-CHANGE with higher pr
		if rc.PreparedRound() > pr {
			return zeroVal[V](), false
		}
		// Ensure at least one ROUND-CHANGE with pr and pv
		if rc.PreparedRound() == pr && rc.PreparedValue() == pv {
			found = true
		}
	}

	return pv, found
}

// getSingleJustifiedPrPv extracts the single justified Pr and Pv from quorum
// PREPARES in list of messages. It expects only one possible combination.
func getSingleJustifiedPrPv[I any, V comparable, C any](d Definition[I, V, C], msgs []Msg[I, V]) (int64, V, bool) {
	var (
		pr    int64
		pv    V
		count int
		uniq  = uniqSource[I, V]()
	)

	for _, msg := range msgs {
		if msg.Type() != MsgPrepare {
			continue
		}

		if !uniq(msg) {
			return 0, zeroVal[V](), false
		}

		if count == 0 {
			pr = msg.Round()
			pv = msg.Value()
		} else if pr != msg.Round() || pv != msg.Value() {
			return 0, zeroVal[V](), false
		}

		count++
	}

	return pr, pv, count >= d.Quorum()
}

// getJustifiedQrc implements algorithm 4:1 and returns a justified quorum ROUND_CHANGEs (Qrc).
func getJustifiedQrc[I any, V comparable, C any](d Definition[I, V, C], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	if qrc, ok := quorumNullPrepared(d, all, round); ok {
		// Return any quorum null pv ROUND_CHANGE messages as Qrc.
		return qrc, true
	}

	roundChanges := filterRoundChange(all, round)

	for _, prepares := range getPrepareQuorums(d, all) {
		// See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) == prepares.Round.
		var (
			qrc                []Msg[I, V]
			hasHighestPrepared bool
			pr                 = prepares[0].Round()
			pv                 = prepares[0].Value()
			uniq               = uniqSource[I, V]()
		)
		for _, rc := range roundChanges {
			if rc.PreparedRound() > pr {
				continue
			}

			if !uniq(rc) {
				continue
			}

			if rc.PreparedRound() == pr && rc.PreparedValue() == pv {
				hasHighestPrepared = true
			}

			qrc = append(qrc, rc)
		}

		if len(qrc) >= d.Quorum() && hasHighestPrepared {
			return append(qrc, prepares...), true
		}
	}

	return nil, false
}

// getFPlus1RoundChanges returns true and Faulty+1 ROUND-CHANGE messages (Frc) with
// the rounds higher than the provided round. It returns the highest round
// per process in order to jump furthest.
func getFPlus1RoundChanges[I any, V comparable, C any](d Definition[I, V, C], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	highestBySource := make(map[int64]Msg[I, V])

	for _, msg := range all {
		if msg.Type() != MsgRoundChange {
			continue
		}

		if msg.Round() <= round {
			continue
		}

		if highest, ok := highestBySource[msg.Source()]; ok && highest.Round() > msg.Round() {
			continue
		}

		highestBySource[msg.Source()] = msg

		if len(highestBySource) == d.Faulty()+1 {
			break
		}
	}

	if len(highestBySource) < d.Faulty()+1 {
		return nil, false
	}

	var resp []Msg[I, V]
	for _, msg := range highestBySource {
		resp = append(resp, msg)
	}

	return resp, true
}

// preparedKey defines the round and value of set of identical PREPARE messages.
type preparedKey[I any, V comparable] struct {
	round int64
	value V
}

// getPrepareQuorums returns all sets of quorum PREPARE messages
// with identical rounds and values.
func getPrepareQuorums[I any, V comparable, C any](d Definition[I, V, C], all []Msg[I, V]) [][]Msg[I, V] {
	sets := make(map[preparedKey[I, V]]map[int64]Msg[I, V]) // map[preparedKey]map[process]Msg

	for _, msg := range all { // Flatten to get PREPARES included as ROUND-CHANGE justifications.
		if msg.Type() != MsgPrepare {
			continue
		}

		key := preparedKey[I, V]{round: msg.Round(), value: msg.Value()}

		msgs, ok := sets[key]
		if !ok {
			msgs = make(map[int64]Msg[I, V])
		}

		msgs[msg.Source()] = msg
		sets[key] = msgs
	}

	// Return all quorums
	var quorums [][]Msg[I, V]

	for _, msgs := range sets {
		if len(msgs) < d.Quorum() {
			continue
		}

		var quorum []Msg[I, V]
		for _, msg := range msgs {
			quorum = append(quorum, msg)
		}

		quorums = append(quorums, quorum)
	}

	return quorums
}

// quorumNullPrepared implements condition J1 and returns Qrc and true if a quorum
// of round changes messages (Qrc) for the round have null prepared round and value.
func quorumNullPrepared[I any, V comparable, C any](d Definition[I, V, C], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	var (
		nullPr int64
		nullPv V
	)

	justification := filterMsgs(all, MsgRoundChange, round, nil, &nullPr, &nullPv)

	return justification, len(justification) >= d.Quorum()
}

// filterByRoundAndValue returns the messages matching the type and value.
func filterByRoundAndValue[I any, V comparable](msgs []Msg[I, V], typ MsgType, round int64, value V) []Msg[I, V] {
	return filterMsgs(msgs, typ, round, &value, nil, nil)
}

// filterRoundChange returns all round change messages for the provided round.
func filterRoundChange[I any, V comparable](msgs []Msg[I, V], round int64) []Msg[I, V] {
	return filterMsgs(msgs, MsgRoundChange, round, nil, nil, nil)
}

// filterMsgs returns one message per process matching the provided type and round
// and optional value, pr, pv.
func filterMsgs[I any, V comparable](msgs []Msg[I, V], typ MsgType, round int64, value *V, pr *int64, pv *V) []Msg[I, V] {
	var (
		resp []Msg[I, V]
		uniq = uniqSource[I, V]()
	)

	for _, msg := range msgs {
		if typ != msg.Type() {
			continue
		}

		if round != msg.Round() {
			continue
		}

		if value != nil && msg.Value() != *value {
			continue
		}

		if pv != nil && msg.PreparedValue() != *pv {
			continue
		}

		if pr != nil && *pr != msg.PreparedRound() {
			continue
		}

		if uniq(msg) {
			resp = append(resp, msg)
		}
	}

	return resp
}

// zeroVal returns a zero value.
func zeroVal[V comparable]() V {
	var zero V
	return zero
}

// isZeroVal returns true if the value is a zero value.
func isZeroVal[V comparable](v V) bool {
	return v == zeroVal[V]()
}

// flatten returns the buffer as a list containing all the buffered messages
// as well as all their justifications.
func flatten[I any, V comparable](buffer map[int64][]Msg[I, V]) []Msg[I, V] {
	var resp []Msg[I, V]

	for _, msgs := range buffer {
		for _, msg := range msgs {
			resp = append(resp, msg)
			for _, j := range msg.Justification() {
				resp = append(resp, j)
				if len(j.Justification()) > 0 {
					panic("bug: nested justifications")
				}
			}
		}
	}

	return resp
}

// uniqSource returns a function that returns true if the message is from a unique source.
func uniqSource[I any, V comparable](msgs ...Msg[I, V]) func(Msg[I, V]) bool {
	dedup := make(map[int64]bool)
	for _, msg := range msgs {
		if dedup[msg.Source()] {
			panic("bug: seeding uniq with duplicates")
		}

		dedup[msg.Source()] = true
	}

	return func(msg Msg[I, V]) bool {
		if dedup[msg.Source()] {
			return false
		}

		dedup[msg.Source()] = true

		return true
	}
}
