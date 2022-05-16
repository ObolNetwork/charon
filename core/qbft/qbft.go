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

// Package qbft is an implementation of the https://arxiv.org/pdf/2002.03613.pdf paper
// referenced by the QBFT spec https://github.com/ConsenSys/qbft-formal-spec-and-verification.
package qbft

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/obolnetwork/charon/app/errors"
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
type Definition[I any, V comparable] struct {
	// IsLeader is a deterministic leader election function.
	IsLeader func(instance I, round, process int64) bool
	// NewTimer returns a new timer channel and stop function for the round.
	NewTimer func(round int64) (<-chan time.Time, func())
	// Decide is called when consensus has been reached on a value.
	Decide func(ctx context.Context, instance I, value V, qcommit []Msg[I, V])
	// LogUponRule allows debug logging of triggered upon rules on message receipt.
	LogUponRule func(ctx context.Context, instance I, process, round int64, msg Msg[I, V], uponRule string)
	// Nodes is the total number of nodes/processes participating in consensus.
	Nodes int
	// FIFOLimit limits the amount of message buffered for each peer.
	FIFOLimit int
}

// Quorum returns the quorum count for the system.
// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
func (d Definition[I, V]) Quorum() int {
	return int(math.Ceil(float64(d.Nodes*2) / 3))
}

// Faulty returns the maximum number of faulty/byzantium nodes supported in the system.
// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
func (d Definition[I, V]) Faulty() int {
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

func (i MsgType) Valid() bool {
	return i > MsgUnknown && i < msgSentinel
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
	// Value being proposed.
	Value() V
	// PreparedRound is the justified prepared round.
	PreparedRound() int64
	// PreparedValue is the justified prepared value.
	PreparedValue() V
	// Justification is the set of messages that explicitly justifies this message.
	Justification() []Msg[I, V]
}

//go:generate stringer -type=uponRule -trimprefix=upon

// uponRule defines the event based rules that are triggered when messages are received.
type uponRule int64

const (
	uponNothing uponRule = iota
	uponJustifiedPrePrepare
	uponQuorumPrepares
	uponQuorumCommits
	uponUnjustQuorumRoundChanges
	uponFPlus1RoundChanges
	uponQuorumRoundChanges
	uponJustifiedDecided
)

// Run executes the consensus algorithm until the context closed.
// The generic type I is the instance of consensus and can be anything.
// The generic type V is the arbitrary data value being proposed; it only requires an Equal method.
//
//nolint:gocognit // It is indeed a complex algorithm.
func Run[I any, V comparable](ctx context.Context, d Definition[I, V], t Transport[I, V], instance I, process int64, inputValue V) (err error) {
	if isZeroVal(inputValue) {
		return errors.New("zero input value not supported")
	}
	defer func() {
		// Panics are used for assertions and sanity checks to reduce lines of code
		// and to improve readability. Catch them here.
		if r := recover(); r != nil {
			err = fmt.Errorf("qbft sanity check: %v", r)
		}
	}()

	// === State ===

	var (
		round                 int64 = 1
		preparedRound         int64
		preparedValue         V
		preparedJustification []Msg[I, V]
		qCommit               []Msg[I, V]
		buffer                = make(map[int64][]Msg[I, V])
		dedupRules            = make(map[uponRule]bool)
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
	isDuplicatedRule := func(rule uponRule) bool {
		if dedupRules[rule] {
			return true
		}

		// First time for this rule
		dedupRules[rule] = true

		return false
	}

	// changeRound changes round and resets the rules deduplication memory.
	changeRound := func(newRound int64) {
		dedupRules = make(map[uponRule]bool)
		round = newRound
	}

	// === Algorithm ===

	{ // Algorithm 1:11
		if d.IsLeader(instance, round, process) { // Note round==1 at this point.
			err := broadcastMsg(MsgPrePrepare, inputValue, nil) // Justification is round==1
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
		case msg := <-t.Receive:
			// Just send Qcommit if consensus already decided
			if len(qCommit) > 0 {
				if msg.Source() != process && msg.Type() == MsgRoundChange { // Algorithm 3:17
					err = broadcastMsg(MsgDecided, qCommit[0].Value(), qCommit)
				}

				break
			}

			if !isJustified(d, instance, msg) { // Drop unjust messages
				d.LogUponRule(ctx, instance, process, round, msg, "unjust"+msg.Type().String())
				break
			}

			bufferMsg(msg)

			rule, justification := classify(d, instance, round, process, buffer, msg)
			if rule == uponNothing || isDuplicatedRule(rule) {
				// Do nothing more if no rule or duplicate rule was triggered
				break
			}

			d.LogUponRule(ctx, instance, process, round, msg, rule.String())

			switch rule {
			case uponJustifiedPrePrepare: // Algorithm 2:1
				// Applicable to current or future rounds (since justified)
				changeRound(msg.Round())

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				err = broadcastMsg(MsgPrepare, msg.Value(), nil)

			case uponQuorumPrepares: // Algorithm 2:4
				// Only applicable to current round
				preparedRound = round /* == msg.Round*/
				preparedValue = msg.Value()
				preparedJustification = justification

				err = broadcastMsg(MsgCommit, preparedValue, nil)

			case uponQuorumCommits, uponJustifiedDecided: // Algorithm 2:8
				// Applicable to any round (since can be justified)
				changeRound(msg.Round())
				qCommit = justification

				stopTimer()
				timerChan = nil

				d.Decide(ctx, instance, msg.Value(), justification)

			case uponFPlus1RoundChanges: // Algorithm 3:5
				// Only applicable to future rounds
				changeRound(nextMinRound(d, justification, round /* < msg.Round */))

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				err = broadcastRoundChange()

			case uponQuorumRoundChanges: // Algorithm 3:11
				// Only applicable to current round
				qrc := filterRoundChange(justification, round /* == msg.Round */)
				_, pv := highestPrepared(qrc)

				value := pv
				if isZeroVal(value) {
					value = inputValue
				}

				err = broadcastMsg(MsgPrePrepare, value, justification)

			case uponUnjustQuorumRoundChanges:
				// Ignore bug or byzantine

			default:
				panic("bug: invalid rule")
			}

		case <-timerChan: // Algorithm 3:1
			round++

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

// classify returns the rule triggered upon receipt of the last message and its justifications.
func classify[I any, V comparable](d Definition[I, V], instance I, round, process int64, buffer map[int64][]Msg[I, V], msg Msg[I, V]) (uponRule, []Msg[I, V]) {
	switch msg.Type() {
	case MsgDecided:
		return uponJustifiedDecided, msg.Justification()

	case MsgPrePrepare:

		// Only ignore old rounds, since PRE-PREPARE is justified we may jump ahead.
		if msg.Round() < round {
			return uponNothing, nil
		}

		return uponJustifiedPrePrepare, nil

	case MsgPrepare:
		// Ignore other rounds, since PREPARE isn't justified.
		if msg.Round() != round {
			return uponNothing, nil
		}
		prepares := filterByRoundAndValue(flatten(buffer), MsgPrepare, msg.Round(), msg.Value())
		if len(prepares) >= d.Quorum() {
			return uponQuorumPrepares, prepares
		}

	case MsgCommit:
		// Ignore other rounds, since COMMIT isn't justified.
		if msg.Round() != round {
			return uponNothing, nil
		}
		commits := filterByRoundAndValue(flatten(buffer), MsgCommit, msg.Round(), msg.Value())
		if len(commits) >= d.Quorum() {
			return uponQuorumCommits, commits
		}

	case MsgRoundChange:
		// Only ignore old rounds.
		if msg.Round() < round {
			return uponNothing, nil
		}

		all := flatten(buffer)

		if msg.Round() > round {
			// Jump ahead if we received F+1 higher ROUND-CHANGEs.
			if frc, ok := getFPlus1RoundChanges(d, all, round); ok {
				return uponFPlus1RoundChanges, frc
			}

			return uponNothing, nil
		}

		/* else msg.Round == round */

		if qrc := filterRoundChange(all, msg.Round()); len(qrc) < d.Quorum() {
			return uponNothing, nil
		}

		qrc, ok := getJustifiedQrc(d, all, msg.Round())
		if !ok {
			return uponUnjustQuorumRoundChanges, nil
		}

		if !d.IsLeader(instance, msg.Round(), process) {
			return uponNothing, nil
		}

		return uponQuorumRoundChanges, qrc

	default:
		panic("bug: invalid type")
	}

	return uponNothing, nil
}

// highestPrepared implements algorithm 4:5 and returns
// the highest prepared round (and pv) from the set of quorum
// round change messages (Qrc).
func highestPrepared[I any, V comparable](qrc []Msg[I, V]) (int64, V) {
	if len(qrc) == 0 {
		// Expect: len(Qrc) >= quorum
		panic("bug: qrc empty")
	}

	var (
		pr int64
		pv V
	)
	for _, msg := range qrc {
		if pr < msg.PreparedRound() {
			pr = msg.PreparedRound()
			pv = msg.PreparedValue()
		}
	}

	return pr, pv
}

// nextMinRound implements algorithm 3:6 and returns the next minimum round
// from received round change messages.
func nextMinRound[I any, V comparable](d Definition[I, V], frc []Msg[I, V], round int64) int64 {
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

// isJustified returns true if message is justified or if it does not need justification
func isJustified[I any, V comparable](d Definition[I, V], instance I, msg Msg[I, V]) bool {
	switch msg.Type() {
	case MsgPrePrepare:
		return IsJustifiedPrePrepare(d, instance, msg)
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
func isJustifiedRoundChange[I any, V comparable](d Definition[I, V], msg Msg[I, V]) bool {
	if msg.Type() != MsgRoundChange {
		panic("bug: not a round change message")
	}

	// ROUND-CHANGE justification contains quorum PREPARE messages that justifies Pr and Pv.
	prepares := msg.Justification()
	pr := msg.PreparedRound()
	pv := msg.PreparedValue()

	if len(prepares) == 0 {
		// If no justification, ensure null prepared round and value.
		return pr == 0 && isZeroVal(pv)
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
func isJustifiedDecided[I any, V comparable](d Definition[I, V], msg Msg[I, V]) bool {
	if msg.Type() != MsgDecided {
		panic("bug: not a decided message")
	}

	v := msg.Value()
	commits := filterMsgs(msg.Justification(), MsgCommit, msg.Round(), &v, nil, nil)

	return len(commits) >= d.Quorum()
}

// IsJustifiedPrePrepare returns true if the PRE-PREPARE message is justified.
func IsJustifiedPrePrepare[I any, V comparable](d Definition[I, V], instance I, msg Msg[I, V]) bool {
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
func containsJustifiedQrc[I any, V comparable](d Definition[I, V], justification []Msg[I, V], round int64) (V, bool) {
	qrc := filterRoundChange(justification, round)
	if len(qrc) < d.Quorum() {
		return zeroVal[V](), false
	}

	// No need to calculate J1 or J2 for all possible combinations,
	// since justification should only contain one.

	// J1: If qrc contains quorum round change messages
	// with null pv and null pr.
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

	// J2: if the justification has a quorum of valid prepare messages
	// with pr and pv equaled to highest pr and pv in qrc (other than null).
	pr, pv := highestPrepared(qrc)
	if pr == 0 {
		panic("bug: highest pr=0, but all not null")
	}

	prepares := filterMsgs(justification, MsgPrepare, pr, &pv, nil, nil)

	return pv, len(prepares) >= d.Quorum()
}

// getJustifiedQrc implements algorithm 4:1 and returns a justified quorum ROUND_CHANGEs (Qrc).
func getJustifiedQrc[I any, V comparable](d Definition[I, V], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
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
func getFPlus1RoundChanges[I any, V comparable](d Definition[I, V], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
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
func getPrepareQuorums[I any, V comparable](d Definition[I, V], all []Msg[I, V]) [][]Msg[I, V] {
	sets := make(map[preparedKey[I, V]]map[int64]Msg[I, V]) // map[preparedKey]map[process]Msg
	for _, msg := range all {                               // Flatten to get PREPARES included as ROUND-CHANGE justifications.
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
func quorumNullPrepared[I any, V comparable](d Definition[I, V], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
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
