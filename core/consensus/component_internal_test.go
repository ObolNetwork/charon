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

package consensus

import (
	"testing"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestDebugRoundChange -update

func TestDebugRoundChange(t *testing.T) {
	const n = 4
	tests := []struct {
		name   string
		msgs   []qbft.Msg[core.Duty, [32]byte]
		round  int64
		leader int
	}{
		{
			name:  "empty",
			round: 1,
		},
		{
			name: "quorum",
			msgs: []qbft.Msg[core.Duty, [32]byte]{
				m(0, qbft.MsgPrePrepare),
				m(0, qbft.MsgPrepare),
				m(1, qbft.MsgPrepare),
				m(2, qbft.MsgPrepare),
				m(1, qbft.MsgCommit),
				m(2, qbft.MsgCommit),
				m(3, qbft.MsgCommit),
			},
			round: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			steps := groupRoundMessages(test.msgs, n, test.round, test.leader)

			var fmtSteps []string
			for _, step := range steps {
				fmtSteps = append(fmtSteps, fmtStepPeers(step))
			}

			testutil.RequireGoldenJSON(t, struct {
				Steps  []string
				Reason string
			}{
				Steps:  fmtSteps,
				Reason: timeoutReason(steps, test.round, test.leader),
			})
		})
	}
}

func m(source int64, typ qbft.MsgType) testMsg {
	return testMsg{
		source: source,
		typ:    typ,
	}
}

type testMsg struct {
	source int64
	typ    qbft.MsgType
}

func (t testMsg) Type() qbft.MsgType {
	return t.typ
}

func (t testMsg) Instance() core.Duty {
	panic("implement me")
}

func (t testMsg) Source() int64 {
	return t.source
}

func (t testMsg) Round() int64 {
	panic("implement me")
}

func (t testMsg) Value() [32]byte {
	panic("implement me")
}

func (t testMsg) PreparedRound() int64 {
	panic("implement me")
}

func (t testMsg) PreparedValue() [32]byte {
	panic("implement me")
}

func (t testMsg) Justification() []qbft.Msg[core.Duty, [32]byte] {
	panic("implement me")
}
