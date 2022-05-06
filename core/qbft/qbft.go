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

	// Receive returns a stream of messages received
	// from other processes in the system (including this process).
	Receive <-chan Msg
}

// Definition defines the consensus system parameters that are external to the qbft algorithm.
// This remains constant across multiple instances of consensus (calls to Run).
type Definition struct {
	// IsLeader is a deterministic leader election function.
	IsLeader func(instance, round, process int64) bool
	// NewTimer returns a new timer channel and stop function for the round.
	NewTimer func(round int64) (<-chan time.Time, func())
	// IsValid validates messages.
	IsValid func(instance int64, msg Msg) bool
	// LogUponRule allows debug logging of triggered upon rules on message receipt.
	LogUponRule func(instance, process, round int64, msg Msg, uponRule string)
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
	Type          MsgType
	Instance      int64
	Source        int64
	Round         int64
	Value         []byte
	PreparedRound int64
	PreparedValue []byte
}

//go:generate stringer -type=uponRule -trimprefix=upon

// uponRule defines the event based rules that are triggered when messages are received.
type uponRule int64

const (
	uponUnknown uponRule = iota
	uponValidPrePrepare
	uponQuorumPrepare
	uponQuorumCommit
	uponMinRoundChange
	uponQuorumRoundChange
)

// Run returns the consensus decided value (Qcommit) or a context closed error.
func Run(ctx context.Context, d Definition, t Transport, instance, process int64, inputValue []byte) (value []byte, err error) {
	if inputValue == nil {
		return nil, errors.New("nil input value not supported")
	}
	defer func() {
		// Errors are unexpected since this algorithm doesn't do IO
		// or have other sources of errors. Panics are used for sanity
		// checks to improve readability. Catch them here.
		if r := recover(); r != nil {
			err = fmt.Errorf("qbft sanity check: %v", r)
		}
	}()

	// === Helpers ==

	// broadcastMsg broadcasts a non-round-change message.
	broadcastMsg := func(typ MsgType, round int64, value []byte) {
		t.Broadcast(Msg{
			Type:     typ,
			Instance: instance,
			Source:   process,
			Round:    round,
			Value:    value,
		})
	}

	// broadcastRoundChange broadcasts a round-change message.
	broadcastRoundChange := func(round int64, pr int64, pv []byte) {
		t.Broadcast(Msg{
			Type:          MsgRoundChange,
			Instance:      instance,
			Source:        process,
			Round:         round,
			PreparedRound: pr,
			PreparedValue: pv,
		})
	}

	// === State ===

	var (
		round         int64 = 1
		preparedRound int64
		preparedValue []byte
		msgs          []Msg
		dedup         = make(map[dedupKey]bool)
		timerChan     <-chan time.Time
		stopTimer     func()
	)

	// === Algrithm ===

	{ // Algorithm 1:11
		if d.IsLeader(instance, round, process) {
			broadcastMsg(MsgPrePrepare, round, inputValue)
		}

		timerChan, stopTimer = d.NewTimer(round)
	}

	// Handle events until finished.
	for {
		select {
		case msg := <-t.Receive:
			if dedup[key(msg)] {
				continue
			}
			dedup[key(msg)] = true

			if !d.IsValid(instance, msg) {
				continue
			}

			msgs = append(msgs, msg)

			rule, ok := classify(d, instance, round, process, msgs, msg)
			if !ok {
				continue
			}

			d.LogUponRule(instance, process, round, msg, rule.String())

			switch rule {
			case uponValidPrePrepare: // Algorithm 2:1
				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastMsg(MsgPrepare, msg.Round, msg.Value)

			case uponQuorumPrepare: // Algorithm 2:4
				preparedRound = msg.Round
				preparedValue = msg.Value
				broadcastMsg(MsgCommit, msg.Round, msg.Value)

			case uponQuorumCommit: // Algorithm 2:8
				stopTimer()

				return msg.Value, nil

			case uponMinRoundChange: // Algorithm 3:5
				round = nextMinRound(d, msgs, round)

				stopTimer()
				timerChan, stopTimer = d.NewTimer(round)

				broadcastRoundChange(round, preparedRound, preparedValue)

			case uponQuorumRoundChange: // Algorithm 3:11
				qrc := filterRoundChange(msgs, msg.Round)
				_, pv := highestPrepared(qrc)

				value := pv
				if value == nil {
					value = inputValue
				}

				broadcastMsg(MsgPrePrepare, round, value)
			default:
				panic("bug: invalid rule")
			}
		case <-timerChan: // Algorithm 3:1
			round++

			stopTimer()
			timerChan, stopTimer = d.NewTimer(round)

			broadcastRoundChange(round, preparedRound, preparedValue)
		case <-ctx.Done():
			// Timeout
			return nil, ctx.Err()
		}
	}
}

// classify returns any rule triggered upon receipt of the last message.
func classify(d Definition, instance, round, process int64, msgs []Msg, msg Msg) (uponRule, bool) {
	switch msg.Type {
	case MsgPrePrepare:
		if msg.Round != round {
			return uponUnknown, false
		}
		if justifyPrePrepare(d, instance, msgs, msg) {
			return uponValidPrePrepare, true
		}
	case MsgPrepare:
		prepareCount := countByValue(msgs, MsgPrepare, msg.Value)
		if prepareCount == d.Quorum {
			return uponQuorumPrepare, true
		}
	case MsgCommit:
		commitCount := countByValue(msgs, MsgCommit, msg.Value)
		if commitCount == d.Quorum {
			return uponQuorumCommit, true
		}
	case MsgRoundChange:
		frc := filterHigherRoundChange(msgs, round)
		if msg.Round > round && len(frc) == d.Faulty+1 {
			return uponMinRoundChange, true
		}

		qrc := filterRoundChange(msgs, round)
		if msg.Round == round &&
			len(qrc) == d.Quorum &&
			d.IsLeader(instance, msg.Round, process) &&
			justifyRoundChange(d, msgs, qrc) {
			return uponQuorumRoundChange, true
		}

		return uponUnknown, false
	default:
		panic("bug: invalid type")
	}

	return uponUnknown, false
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
	frc := filterHigherRoundChange(msgs, round)

	// Sanity check
	if len(frc) < d.Faulty+1 {
		panic("bug: too few round change messages")
	}

	// Get the smallest round in the set.
	rmin := int64(math.MaxInt64)
	for _, msg := range frc {
		if rmin > msg.Round {
			rmin = msg.Round
		}
	}

	return rmin
}

// justifyRoundChange implements algorithm 4:1 and returns true
// if the latest round change message was justified.
func justifyRoundChange(d Definition, all, qrc []Msg) bool {
	if len(qrc) < d.Quorum {
		return false
	}

	if qrcNoPrepared(qrc) {
		return true
	}

	_, ok := qrcHighestPrepared(d, all, qrc)
	if !ok {
		return false
	}

	return true
}

// justifyPrePrepare implements algorithm 4:3 and returns true if latest
// preprepare message is justified.
func justifyPrePrepare(d Definition, instance int64, msgs []Msg, msg Msg) bool {
	if msg.Type != MsgPrePrepare {
		panic("bug: not d preprepare message")
	}

	if !d.IsLeader(instance, msg.Round, msg.Source) {
		return false
	}

	if msg.Round == 1 {
		return true
	}

	qrc := filterRoundChange(msgs, msg.Round)
	if len(qrc) < d.Quorum {
		return false
	}

	if qrcNoPrepared(qrc) {
		return true
	}

	pv, ok := qrcHighestPrepared(d, msgs, qrc)
	if !ok {
		return false
	} else if !bytes.Equal(pv, msg.Value) {
		return false
	}

	return true
}

// qrcNoPrepared implements condition J1 and returns true if all
// quorom round changes messages (Qrc) have no prepared round or value.
func qrcNoPrepared(qrc []Msg) bool {
	for _, msg := range qrc {
		if msg.Type != MsgRoundChange {
			panic("bug: invalid Qrc set")
		}
		if msg.PreparedRound != 0 || msg.PreparedValue != nil {
			return false
		}
	}

	return true
}

// qrcHighestPrepared implements condition J2 and returns true (and pv) if
// quorum prepare messages with highest pv was received.
func qrcHighestPrepared(d Definition, all []Msg, qrc []Msg) ([]byte, bool) {
	pr, pv := highestPrepared(qrc)
	if pr == 0 {
		return nil, false
	}

	if countByValue(all, MsgPrepare, pv) < d.Quorum {
		return nil, false
	}

	return pv, true
}

// countByValue returns the number of messages matching the type and value.
func countByValue(msgs []Msg, typ MsgType, value []byte) int {
	return len(filterMsgs(msgs, typ, nil, &value, nil, nil))
}

// filterRoundChange returns all round change messages for the provided round.
func filterRoundChange(msgs []Msg, round int64) []Msg {
	return filterMsgs(msgs, MsgRoundChange, &round, nil, nil, nil)
}

// filterHigherRoundChange returns the all round change messages with round higher than the provided round.
func filterHigherRoundChange(msgs []Msg, round int64) []Msg {
	var resp []Msg
	for _, msg := range filterMsgs(msgs, MsgRoundChange, nil, nil, nil, nil) {
		if msg.Round <= round {
			continue
		}
		resp = append(resp, msg)
	}

	return resp
}

// filterMsgs returns the first message per process matching the provided type
// and the optional round, value, pr, pv.
func filterMsgs(msgs []Msg, typ MsgType, round *int64, value *[]byte, pr *int64, pv *[]byte) []Msg {
	var (
		resp []Msg
		dups = make(map[int64]bool)
	)
	for _, msg := range msgs {
		if typ != msg.Type {
			continue
		}

		if round != nil && *round != msg.Round {
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

		if dups[msg.Source] {
			continue
		}

		dups[msg.Source] = true
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
