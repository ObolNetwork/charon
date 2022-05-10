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

// Value defines the constraints of the generic value type.
// The only constraint is an equality method.
type Value[V any] interface {
	Equal(V) bool
}

// Transport abstracts the transport layer between processes in the consensus system.
//
// Note that broadcasting doesn't return an error. Since this algorithm is idempotent
// it is suggested to just retry broadcasting indefinitely until it succeeds or times out.
type Transport[I any, V Value[V]] struct {
	// Broadcast sends a message with the provided fields to all other
	// processes in the system (including this process).
	Broadcast func(typ MsgType, instance I, source int64, round int64, value V, pr int64, pv V, justification []Msg[I, V])

	// SendQCommit sends the commit messages to a specific process.
	SendQCommit func(target int64, qCommit []Msg[I, V])

	// Receive returns a stream of messages received
	// from other processes in the system (including this process).
	Receive <-chan Msg[I, V]
}

// Definition defines the consensus system parameters that are external to the qbft algorithm.
// This remains constant across multiple instances of consensus (calls to Run).
type Definition[I any, V Value[V]] struct {
	// IsLeader is a deterministic leader election function.
	IsLeader func(instance I, round, process int64) bool
	// NewTimer returns a new timer channel and stop function for the round.
	NewTimer func(round int64) (<-chan time.Time, func())
	// Decide is called when consensus has been reached on a value.
	Decide func(instance I, value V, qcommit []Msg[I, V])
	// LogUponRule allows debug logging of triggered upon rules on message receipt.
	LogUponRule func(instance I, process, round int64, msg Msg[I, V], uponRule string)
	// Nodes is the total number of nodes/processes participating in consensus.
	Nodes int
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
	msgSentinel    MsgType = 5
)

func (i MsgType) Valid() bool {
	return i > MsgUnknown && i < msgSentinel
}

// Msg defines the inter process messages.
type Msg[I any, V Value[V]] interface {
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
	uponUnjustPrePrepare
	uponQuorumPrepares
	uponQuorumCommits
	uponUnjustRoundChange
	uponFPlus1RoundChanges
	uponQuorumRoundChanges
)

// Run executes the consensus algorithm until the context closed.
// The generic type I is the instance of consensus and can be anything.
// The generic type V is the arbitrary data value being proposed; it only requires an Equal method.
//
//nolint:gocognit // It is indeed a complex algorithm.
func Run[I any, V Value[V]](ctx context.Context, d Definition[I, V], t Transport[I, V], instance I, process int64, inputValue V) (err error) {
	if isZeroVal(inputValue) {
		return errors.New("zero input value not supported")
	}
	defer func() {
		// Errors are unexpected since this algorithm doesn't do IO
		// or have other sources of errors. Panics are used for sanity
		// checks to improve readability. Catch them here.
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
		buffer                []Msg[I, V]
		dedupIn               = make(map[dedupKey]bool)
		timerChan             <-chan time.Time
		stopTimer             func()
	)

	// === Helpers ==

	// broadcastMsg broadcasts a non-ROUND-CHANGE message for current round.
	broadcastMsg := func(typ MsgType, value V, justification []Msg[I, V]) {
		t.Broadcast(typ, instance, process, round,
			value, 0, zeroVal[V](), justification)
	}

	// broadcastRoundChange broadcasts a ROUND-CHANGE message with current state.
	broadcastRoundChange := func() {
		t.Broadcast(MsgRoundChange, instance, process, round,
			zeroVal[V](), preparedRound, preparedValue, preparedJustification)
	}

	// sendQCommit sends qCommit to the target process.
	sendQCommit := func(target int64) {
		if len(qCommit) == 0 {
			panic("bug: send empty Qcommit")
		}
		t.SendQCommit(target, qCommit)
	}

	// bufferMsg returns true if the message is unique and was added to the buffer.
	// It returns false if the message is a duplicate and should be discarded.
	bufferMsg := func(msg Msg[I, V]) bool {
		if dedupIn[key(msg)] {
			return false
		}
		dedupIn[key(msg)] = true
		buffer = append(buffer, msg)

		return true
	}

	// trimBuffer drops all older round's buffered messages.
	trimBuffer := func() {
		var selected []Msg[I, V]
		for _, msg := range buffer {
			if msg.Round() >= round-1 {
				selected = append(selected, msg)
			}
		}
		buffer = selected

		dedup := make(map[dedupKey]bool)
		for k := range dedupIn {
			if k.Round >= round {
				dedup[k] = true
			}
		}
		dedupIn = dedup
	}

	// === Algorithm ===

	{ // Algorithm 1:11
		if d.IsLeader(instance, round, process) { // Note round==1 at this point.
			broadcastMsg(MsgPrePrepare, inputValue, nil) // Justification is round==1
		}

		timerChan, stopTimer = d.NewTimer(round)
	}

	// Handle events until cancelled.
	for {
		select {
		case msg := <-t.Receive:
			// Just send Qcommit if consensus already decided
			if len(qCommit) > 0 {
				if msg.Source() != process && msg.Type() == MsgRoundChange { // Algorithm 3:17
					sendQCommit(msg.Source())
				}

				continue
			}

			// Buffer message
			if !bufferMsg(msg) {
				continue
			}

			rule, justification := classify(d, instance, round, process, buffer, msg)
			if rule == uponNothing {
				continue
			}

			d.LogUponRule(instance, process, round, msg, rule.String())

			switch rule {
			case uponJustifiedPrePrepare: // Algorithm 2:1
				// Applicable to current or future rounds (since justified)
				round = msg.Round()
				trimBuffer()

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastMsg(MsgPrepare, msg.Value(), nil)

			case uponQuorumPrepares: // Algorithm 2:4
				// Only applicable to current round
				preparedRound = round /* == msg.Round*/
				preparedValue = msg.Value()
				preparedJustification = justification

				broadcastMsg(MsgCommit, preparedValue, nil)

			case uponQuorumCommits: // Algorithm 2:8
				// Applicable to any round (since can be justified)
				stopTimer()
				qCommit = justification

				d.Decide(instance, msg.Value(), justification)

			case uponFPlus1RoundChanges: // Algorithm 3:5
				// Only applicable to future rounds
				round = nextMinRound(d, justification, round /* < msg.Round */)
				trimBuffer()

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastRoundChange()

			case uponQuorumRoundChanges: // Algorithm 3:11
				// Only applicable to current round
				qrc := filterRoundChange(justification, round /* == msg.Round */)
				_, pv := highestPrepared(qrc)

				value := pv
				if isZeroVal(value) {
					value = inputValue
				}

				broadcastMsg(MsgPrePrepare, value, justification)

			case uponUnjustPrePrepare, uponUnjustRoundChange:
				// Ignore bug or byzantium.

			default:
				panic("bug: invalid rule")
			}

		case <-timerChan: // Algorithm 3:1
			round++
			trimBuffer()

			stopTimer()
			timerChan, stopTimer = d.NewTimer(round)

			broadcastRoundChange()

		case <-ctx.Done(): // Cancelled
			return ctx.Err()
		}
	}
}

// classify returns the rule triggered upon receipt of the last message and its justifications.
func classify[I any, V Value[V]](d Definition[I, V], instance I, round, process int64, buffer []Msg[I, V], msg Msg[I, V]) (uponRule, []Msg[I, V]) {
	switch msg.Type() {
	case MsgPrePrepare:
		if !isJustifiedPrePrepare(d, instance, msg) {
			return uponUnjustPrePrepare, nil
		}

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
		prepares := filterByRoundAndValue(buffer, MsgPrepare, msg.Round(), msg.Value())
		if len(prepares) >= d.Quorum() {
			return uponQuorumPrepares, prepares
		}

	case MsgCommit:
		// Don't ignore any rounds, since COMMIT may be justified with Qcommit.
		commits := filterByRoundAndValue(buffer, MsgCommit, msg.Round(), msg.Value())
		if len(commits) >= d.Quorum() {
			return uponQuorumCommits, commits
		}

	case MsgRoundChange:
		if !isJustifiedRoundChange(d, msg) {
			return uponUnjustRoundChange, nil
		}

		// Only ignore old rounds.
		if msg.Round() < round {
			return uponNothing, nil
		}

		if msg.Round() > round {
			// Jump ahead if we received F+1 higher ROUND-CHANGEs.
			if frc, ok := getFPlus1RoundChanges(d, buffer, round); ok {
				return uponFPlus1RoundChanges, frc
			}

			return uponNothing, nil
		}

		/* else msg.Round == round */

		if qrc := filterRoundChange(buffer, msg.Round()); len(qrc) < d.Quorum() {
			return uponNothing, nil
		}

		qrc, ok := getJustifiedQrc(d, buffer, msg.Round())
		if !ok {
			panic("bug: unjust Qrc")
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
func highestPrepared[I any, V Value[V]](qrc []Msg[I, V]) (int64, V) {
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
func nextMinRound[I any, V Value[V]](d Definition[I, V], frc []Msg[I, V], round int64) int64 {
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

// isJustifiedRoundChange returns true if the ROUND_CHANGE message's
// prepared round and value is justified.
func isJustifiedRoundChange[I any, V Value[V]](d Definition[I, V], msg Msg[I, V]) bool {
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

	for _, prepare := range prepares {
		if prepare.Type() != MsgPrepare {
			return false
		}
		if prepare.Round() != pr {
			return false
		}
		if !prepare.Value().Equal(pv) {
			return false
		}
	}

	return true
}

// isJustifiedPrePrepare returns true if the PRE-PREPARE message is justified.
func isJustifiedPrePrepare[I any, V Value[V]](d Definition[I, V], instance I, msg Msg[I, V]) bool {
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

	return msg.Value().Equal(pv) // Ensure Pv is being proposed
}

// containsJustifiedQrc implements algorithm 4:1 and returns true and pv if
// the messages contains a justified quorum ROUND_CHANGEs (Qrc).
func containsJustifiedQrc[I any, V Value[V]](d Definition[I, V], justification []Msg[I, V], round int64) (V, bool) {
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
func getJustifiedQrc[I any, V Value[V]](d Definition[I, V], buffer []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	if qrc, ok := quorumNullPrepared(d, buffer, round); ok {
		// Return any quorum null pv ROUND_CHANGE messages as Qrc.
		return qrc, true
	}

	roundChanges := filterRoundChange(buffer, round)

	for _, prepares := range getPrepareQuorums(d, buffer) {
		// See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) == prepares.Round.
		var (
			qrc                []Msg[I, V]
			hasHighestPrepared bool
			pr                 = prepares[0].Round()
			pv                 = prepares[0].Value()
		)
		for _, rc := range roundChanges {
			if rc.PreparedRound() > pr {
				continue
			}
			if rc.PreparedRound() == pr && rc.PreparedValue().Equal(pv) {
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
func getFPlus1RoundChanges[I any, V Value[V]](d Definition[I, V], buffer []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	highestBySource := make(map[int64]Msg[I, V])
	for _, msg := range buffer {
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

// prepareSet defines a set of PREPARE messages (one per process)
// with identical round and value.
type prepareSet[I any, V Value[V]] struct {
	round int64
	value V
	msgs  map[int64]Msg[I, V] // map[process]Msg
}

// getPrepareQuorums returns all sets of quorum PREPARE messages
// with identical rounds and values.
func getPrepareQuorums[I any, V Value[V]](d Definition[I, V], buffer []Msg[I, V]) [][]Msg[I, V] {
	var sets []prepareSet[I, V]
	for _, msg := range flatten(buffer) { // Flatten to get PREPARES included as ROUND-CHANGE justifications.
		if msg.Type() != MsgPrepare {
			continue
		}

		var found bool
		for _, s := range sets {
			if s.round != msg.Round() || !s.value.Equal(msg.Value()) {
				continue
			}
			s.msgs[msg.Source()] = msg
			found = true

			break
		}
		if found {
			continue
		}

		sets = append(sets, prepareSet[I, V]{
			round: msg.Round(),
			value: msg.Value(),
			msgs:  map[int64]Msg[I, V]{msg.Source(): msg},
		})
	}

	// Return all quorums
	var quorums [][]Msg[I, V]
	for _, set := range sets {
		if len(set.msgs) < d.Quorum() {
			continue
		}
		var quorum []Msg[I, V]
		for _, msg := range set.msgs {
			quorum = append(quorum, msg)
		}
		quorums = append(quorums, quorum)
	}

	return quorums
}

// quorumNullPrepared implements condition J1 and returns Qrc and true if a quorum
// of round changes messages (Qrc) for the round have null prepared round and value.
func quorumNullPrepared[I any, V Value[V]](d Definition[I, V], all []Msg[I, V], round int64) ([]Msg[I, V], bool) {
	var (
		nullPr int64
		nullPv V
	)
	justification := filterMsgs(all, MsgRoundChange, round, nil, &nullPr, &nullPv)

	return justification, len(justification) >= d.Quorum()
}

// filterByRoundAndValue returns the messages matching the type and value.
func filterByRoundAndValue[I any, V Value[V]](msgs []Msg[I, V], typ MsgType, round int64, value V) []Msg[I, V] {
	return filterMsgs(msgs, typ, round, &value, nil, nil)
}

// filterRoundChange returns all round change messages for the provided round.
func filterRoundChange[I any, V Value[V]](msgs []Msg[I, V], round int64) []Msg[I, V] {
	return filterMsgs(msgs, MsgRoundChange, round, nil, nil, nil)
}

// filterMsgs returns one message per process matching the provided type and round
// and optional value, pr, pv.
func filterMsgs[I any, V Value[V]](msgs []Msg[I, V], typ MsgType, round int64, value *V, pr *int64, pv *V) []Msg[I, V] {
	var (
		resp []Msg[I, V]
		dups = make(map[dedupKey]bool)
	)
	for _, msg := range msgs {
		if typ != msg.Type() {
			continue
		}

		if round != msg.Round() {
			continue
		}

		if value != nil && !msg.Value().Equal(*value) {
			continue
		}

		if pv != nil && !msg.PreparedValue().Equal(*pv) {
			continue
		}

		if pr != nil && *pr != msg.PreparedRound() {
			continue
		}

		if dups[key(msg)] {
			continue
		}
		dups[key(msg)] = true
		resp = append(resp, msg)
	}

	return resp
}

// key returns the message dedup key.
func key[I any, V Value[V]](msg Msg[I, V]) dedupKey {
	return dedupKey{
		Source: msg.Source(),
		Type:   msg.Type(),
		Round:  msg.Round(),
	}
}

// dedupKey provides the key to dedup received messages.
type dedupKey struct {
	Source int64
	Type   MsgType
	Round  int64
}

func zeroVal[V Value[V]]() V {
	var zero V
	return zero
}

func isZeroVal[V Value[V]](v V) bool {
	return v.Equal(zeroVal[V]())
}

// flatten returns a new list of messages containing all the buffered messages
// as well as all their justifications.
func flatten[I any, V Value[V]](buffer []Msg[I, V]) []Msg[I, V] {
	var resp []Msg[I, V]
	for _, msg := range buffer {
		resp = append(resp, msg)
		for _, j := range msg.Justification() {
			resp = append(resp, j)
		}
	}

	return resp
}
