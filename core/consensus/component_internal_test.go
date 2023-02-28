// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
			name:  "empty-1",
			round: 1,
		},
		{
			name:  "empty-2",
			round: 2,
		},
		{
			name: "quorum",
			msgs: []qbft.Msg[core.Duty, [32]byte]{
				m(0, qbft.MsgRoundChange),
				m(1, qbft.MsgRoundChange),
				m(2, qbft.MsgRoundChange),
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
				Reason: timeoutReason(steps, test.round, 3),
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
