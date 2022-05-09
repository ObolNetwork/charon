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
	"bytes"
	"context"
	"fmt"
	"math"
	"time"

	"github.com/obolnetwork/charon/app/errors"
)

// Transport abstracts the transport layer between processes in the consensus system.
//
// Note that broadcasting doesn't return an error. Since this algorithm is idempotent
// it is suggested to just retry broadcasting indefinitely until it succeeds or times out.
type Transport struct {
	// Broadcast sends the message to all other
	// processes in the system (including this process).
	Broadcast func(Msg)

	// SendQCommit sends the commit messages to a specific process.
	SendQCommit func(target int64, qCommit []Msg)

	// Receive returns a stream of messages received
	// from other processes in the system (including this process).
	Receive <-chan Msg
}

// Definition defines the consensus system parameters that are external to the qbft algorithm.
// This remains constant across multiple instances of consensus (calls to Run).
type Definition struct {
	// IsLeader is a deterministic leader election function.
	IsLeader func(instance []byte, round, process int64) bool
	// NewTimer returns a new timer channel and stop function for the round.
	NewTimer func(round int64) (<-chan time.Time, func())
	// Decide is called when consensus has been reached on a value.
	Decide func(instance []byte, value []byte, qcommit []Msg)
	// LogUponRule allows debug logging of triggered upon rules on message receipt.
	LogUponRule func(instance []byte, process, round int64, msg Msg, uponRule string)
	// Quorum is the quorum count for the system.
	Quorum int
	// Faulty is the maximum faulty process count for the system.
	Faulty int
}

//go:generate stringer -type=MsgType

// MsgType defines the QBFT message types.
type MsgType int64

const (
	MsgPrePrepare MsgType = iota + 1
	MsgPrepare
	MsgCommit
	MsgRoundChange
)

// Msg defines the inter process messages.
type Msg struct {
	// Type of the message.
	Type MsgType
	// Instance identifies the consensus instance.
	Instance []byte
	// Source identifies the process that sent the message.
	Source int64
	// Round the message pertains to.
	Round int64
	// Value being proposed.
	Value []byte
	// PreparedRound is the justified prepared round.
	PreparedRound int64
	// PreparedValue is the justified prepared value.
	PreparedValue []byte
	// Justify is the set of messages that explicitly justifies this message.
	Justify []Msg
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
//nolint:gocognit // If is indeed a complex algorithm.
func Run(ctx context.Context, d Definition, t Transport, instance []byte, process int64, inputValue []byte) (err error) {
	if inputValue == nil {
		return errors.New("nil input value not supported")
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
		round           int64 = 1
		preparedRound   int64
		preparedValue   []byte
		preparedJustify []Msg
		qCommit         []Msg
		buffer          []Msg
		dedupIn         = make(map[dedupKey]bool)
		timerChan       <-chan time.Time
		stopTimer       func()
	)

	// === Helpers ==

	// broadcastMsg broadcasts a non-ROUND-CHANGE message for current round.
	broadcastMsg := func(typ MsgType, value []byte, justify []Msg) {
		t.Broadcast(Msg{
			Type:     typ,
			Instance: instance,
			Source:   process,
			Round:    round,
			Value:    value,
			Justify:  justify,
		})
	}

	// broadcastRoundChange broadcasts a ROUND-CHANGE message with current state.
	broadcastRoundChange := func() {
		t.Broadcast(Msg{
			Type:          MsgRoundChange,
			Instance:      instance,
			Source:        process,
			Round:         round,
			PreparedRound: preparedRound,
			PreparedValue: preparedValue,
			Justify:       preparedJustify,
		})
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
	bufferMsg := func(msg Msg) bool {
		if dedupIn[key(msg)] {
			return false
		}
		dedupIn[key(msg)] = true
		buffer = append(buffer, msg)

		return true
	}

	// trimBuffer drops all older round's buffered messages.
	trimBuffer := func() {
		var selected []Msg
		for _, msg := range buffer {
			if msg.Round >= round {
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
				if msg.Source != process && msg.Type == MsgRoundChange { // Algorithm 3:17
					sendQCommit(msg.Source)
				}

				continue
			}

			// Buffer message
			if !bufferMsg(msg) {
				continue
			}

			// Buffer justifications
			for _, j := range msg.Justify {
				if !bufferMsg(j) {
					continue
				}
			}

			rule, justify := classify(d, instance, round, process, buffer, msg)
			if rule == uponNothing {
				continue
			}

			d.LogUponRule(instance, process, round, msg, rule.String())

			switch rule {
			case uponJustifiedPrePrepare: // Algorithm 2:1
				// Applicable to current or future rounds (since justified)
				round = msg.Round
				trimBuffer()

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastMsg(MsgPrepare, msg.Value, nil)

			case uponQuorumPrepares: // Algorithm 2:4
				// Only applicable to current round
				preparedRound = round /* == msg.Round*/
				preparedValue = msg.Value
				preparedJustify = justify

				broadcastMsg(MsgCommit, preparedValue, nil)

			case uponQuorumCommits: // Algorithm 2:8
				// Applicable to any round (since can be justified)
				stopTimer()
				qCommit = justify

				d.Decide(instance, msg.Value, justify)

			case uponFPlus1RoundChanges: // Algorithm 3:5
				// Only applicable to future rounds
				round = nextMinRound(d, justify, round /* < msg.Round*/)
				trimBuffer()

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastRoundChange()

			case uponQuorumRoundChanges: // Algorithm 3:11
				// Only applicable to current round
				qrc := filterRoundChange(justify, round /* == msg.Round*/)
				_, pv := highestPrepared(qrc)

				value := pv
				if value == nil {
					value = inputValue
				}

				broadcastMsg(MsgPrePrepare, value, justify)

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
func classify(d Definition, instance []byte, round, process int64, buffer []Msg, msg Msg) (uponRule, []Msg) {
	switch msg.Type {
	case MsgPrePrepare:
		if !isJustifiedPrePrepare(d, instance, msg) {
			return uponUnjustPrePrepare, nil
		}

		// Only ignore old rounds, since PRE-PREPARE is justified we may jump ahead.
		if msg.Round < round {
			return uponNothing, nil
		}

		return uponJustifiedPrePrepare, nil

	case MsgPrepare:
		// Ignore other rounds, since PREPARE isn't justified.
		if msg.Round != round {
			return uponNothing, nil
		}
		prepares := filterByRoundAndValue(buffer, MsgPrepare, msg.Round, msg.Value)
		if len(prepares) >= d.Quorum {
			return uponQuorumPrepares, prepares
		}

	case MsgCommit:
		// Don't ignore any rounds, since COMMIT may be justified with Qcommit.
		commits := filterByRoundAndValue(buffer, MsgCommit, msg.Round, msg.Value)
		if len(commits) >= d.Quorum {
			return uponQuorumCommits, commits
		}

	case MsgRoundChange:
		if !isJustifiedRoundChange(d, msg) {
			return uponUnjustRoundChange, nil
		}

		// Only ignore old rounds.
		if msg.Round < round {
			return uponNothing, nil
		}

		if msg.Round > round {
			// Jump ahead if we received F+1 higher ROUND-CHANGEs.
			if frc, ok := getFPlus1RoundChanges(d, buffer, round); ok {
				return uponFPlus1RoundChanges, frc
			}

			return uponNothing, nil
		}

		/* else msg.Round == round */

		if !d.IsLeader(instance, msg.Round, process) {
			return uponNothing, nil
		}

		if qrc, ok := getJustifiedQrc(d, buffer, msg.Round); ok {
			return uponQuorumRoundChanges, qrc
		}

	default:
		panic("bug: invalid type")
	}

	return uponNothing, nil
}

// highestPrepared implements algorithm 4:5 and returns
// the highest prepared round (and pv) from the set of quorum
// round change messages (Qrc).
func highestPrepared(qrc []Msg) (int64, []byte) {
	if len(qrc) == 0 {
		// Expect: len(Qrc) >= quorum
		panic("bug: qrc empty")
	}

	var (
		pr int64
		pv []byte
	)
	for _, msg := range qrc {
		if pr < msg.PreparedRound {
			pr = msg.PreparedRound
			pv = msg.PreparedValue
		}
	}

	return pr, pv
}

// nextMinRound implements algorithm 3:6 and returns the next minimum round
// from received round change messages.
func nextMinRound(d Definition, msgs []Msg, round int64) int64 {
	// Get all RoundChange messages with round (rj) higher than current round (ri)
	frc, ok := getFPlus1RoundChanges(d, msgs, round)
	if !ok {
		panic("bug: too few round change messages")
	}

	// Get the smallest round in the set.
	rmin := int64(math.MaxInt64)
	for _, msg := range frc {
		if rmin > msg.Round {
			rmin = msg.Round
		}
	}

	if rmin <= round {
		panic("bug: next rmin not after round")
	}

	return rmin
}

// isJustifiedRoundChange returns true if the ROUND_CHANGE message's
// prepared round and value is justified.
func isJustifiedRoundChange(d Definition, msg Msg) bool {
	if msg.Type != MsgRoundChange {
		panic("bug: not a round change message")
	}

	if msg.PreparedRound == 0 && msg.PreparedValue == nil && len(msg.Justify) == 0 {
		// No need to justify null prepared round and value.
		return true
	}

	// No need to check for all possible combinations, since justified should only contain a one.

	if len(msg.Justify) < d.Quorum {
		return false
	}

	prepares := filterMsgs(msg.Justify, MsgPrepare, msg.PreparedRound, &msg.PreparedValue, nil, nil)

	return len(msg.Justify) == len(prepares)
}

// isJustifiedPrePrepare returns true if the PRE-PREPARE message is justified.
func isJustifiedPrePrepare(d Definition, instance []byte, msg Msg) bool {
	if msg.Type != MsgPrePrepare {
		panic("bug: not a preprepare message")
	}

	if !d.IsLeader(instance, msg.Round, msg.Source) {
		return false
	}

	if msg.Round == 1 {
		return true
	}

	pv, ok := containsJustifiedQrc(d, msg.Justify, msg.Round)
	if !ok {
		return false
	}

	if pv == nil {
		return true // New value being proposed
	}

	if bytes.Equal(msg.Value, pv) {
		return true
	}

	return false
}

// containsJustifiedQrc implements algorithm 4:1 and returns true and pv if
// the messages contains a justified quorum ROUND_CHANGEs (Qrc).
func containsJustifiedQrc(d Definition, justify []Msg, round int64) ([]byte, bool) {
	qrc := filterRoundChange(justify, round)
	if len(qrc) < d.Quorum {
		return nil, false
	}

	// No need to calculate J1 or J2 for all possible combinations,
	// since justification should only contain one.

	// J1: If qrc contains quorum round change messages
	// with null pv and null pr.
	allNull := true
	for _, rc := range qrc {
		if rc.PreparedRound != 0 || rc.PreparedValue != nil {
			allNull = false
			break
		}
	}
	if allNull {
		return nil, true
	}

	// J2: if the justification has a quorum of valid prepare messages
	// with pr and pv equaled to highest pr and pv in qrc (other than null).
	pr, pv := highestPrepared(qrc)
	if pr == 0 {
		panic("bug: highest pr=0, but all not null")
	}

	prepares := filterMsgs(justify, MsgPrepare, pr, &pv, nil, nil)

	return pv, len(prepares) >= d.Quorum
}

// getJustifiedQrc implements algorithm 4:1 and returns a justified quorum ROUND_CHANGEs (Qrc).
func getJustifiedQrc(d Definition, all []Msg, round int64) ([]Msg, bool) {
	if qrc, ok := quorumNullPrepared(d, all, round); ok {
		// Return any quorum null pv ROUND_CHANGE messages as Qrc.
		return qrc, true
	}

	rc := filterRoundChange(all, round)
	for _, prepares := range getPrepareQuorums(d, all) {
		// See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) == prepares.Round.
		var (
			qrc                []Msg
			hasHighestPrepared bool
			pr                 = prepares[0].Round
			pv                 = prepares[0].Value
		)
		for _, msg := range rc {
			if !bytes.Equal(msg.PreparedValue, pv) {
				continue
			}
			if msg.PreparedRound > pr {
				continue
			}
			if msg.PreparedRound == pr {
				hasHighestPrepared = true
			}
			qrc = append(qrc, msg)
		}
		if len(qrc) >= d.Quorum && hasHighestPrepared {
			return append(qrc, prepares...), true
		}
	}

	return nil, false
}

// getFPlus1RoundChanges returns true and Faulty+1 ROUND-CHANGE messages (Frc) with
// the rounds higher than the provided round. It returns the highest round
// per process in order to jump furthest.
func getFPlus1RoundChanges(d Definition, msgs []Msg, round int64) ([]Msg, bool) {
	highestBySource := make(map[int64]Msg)
	for _, msg := range msgs {
		if msg.Type != MsgRoundChange {
			continue
		}
		if msg.Round <= round {
			continue
		}
		if highestBySource[msg.Source].Round > msg.Round {
			continue
		}

		highestBySource[msg.Source] = msg

		if len(highestBySource) == d.Faulty+1 {
			break
		}
	}

	if len(highestBySource) < d.Faulty+1 {
		return nil, false
	}

	var resp []Msg
	for _, msg := range highestBySource {
		resp = append(resp, msg)
	}

	return resp, true
}

// getPrepareQuorums returns all sets of quorum PREPARE messages
// with identical rounds and values.
func getPrepareQuorums(d Definition, msgs []Msg) [][]Msg {
	sets := make(map[string]map[int64]Msg) // map[round+value]map[process]Msg
	for _, msg := range msgs {
		if msg.Type != MsgPrepare {
			continue
		}
		key := fmt.Sprintf("%d/%s", msg.Round, msg.Value)
		msgs, ok := sets[key]
		if !ok {
			msgs = make(map[int64]Msg)
		}
		msgs[msg.Source] = msg
		sets[key] = msgs
	}

	// Return all quorums
	var quorums [][]Msg
	for _, msgs := range sets {
		if len(msgs) < d.Quorum {
			continue
		}
		var quorum []Msg
		for _, msg := range msgs {
			quorum = append(quorum, msg)
		}
		quorums = append(quorums, quorum)
	}

	return quorums
}

// quorumNullPrepared implements condition J1 and returns Qrc and true if a quorum
// of round changes messages (Qrc) for the round have null prepared round and value.
func quorumNullPrepared(d Definition, all []Msg, round int64) ([]Msg, bool) {
	var (
		nullPr int64
		nullPv []byte
	)
	justify := filterMsgs(all, MsgRoundChange, round, nil, &nullPr, &nullPv)

	return justify, len(justify) >= d.Quorum
}

// filterByRoundAndValue returns the messages matching the type and value.
func filterByRoundAndValue(msgs []Msg, typ MsgType, round int64, value []byte) []Msg {
	return filterMsgs(msgs, typ, round, &value, nil, nil)
}

// filterRoundChange returns all round change messages for the provided round.
func filterRoundChange(msgs []Msg, round int64) []Msg {
	return filterMsgs(msgs, MsgRoundChange, round, nil, nil, nil)
}

// filterMsgs returns one message per process matching the provided type and round
// and optional value, pr, pv.
func filterMsgs(msgs []Msg, typ MsgType, round int64, value *[]byte, pr *int64, pv *[]byte) []Msg {
	var (
		resp []Msg
		dups = make(map[dedupKey]bool)
	)
	for _, msg := range msgs {
		if typ != msg.Type {
			continue
		}

		if round != msg.Round {
			continue
		}

		if value != nil && !bytes.Equal(*value, msg.Value) {
			continue
		}

		if pv != nil && !bytes.Equal(*pv, msg.PreparedValue) {
			continue
		}

		if pr != nil && *pr != msg.PreparedRound {
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
func key(msg Msg) dedupKey {
	return dedupKey{
		Source: msg.Source,
		Type:   msg.Type,
		Round:  msg.Round,
	}
}

// dedupKey provides the key to dedup received messages.
type dedupKey struct {
	Source int64
	Type   MsgType
	Round  int64
}
