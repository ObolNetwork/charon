// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"bytes"
	"context"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
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

func TestComponent_handle(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(base *pbv1.ConsensusMsg, c *Component)
		checkErr func(err error)
	}{
		{
			"qbft message with no pubkey errors",
			func(base *pbv1.ConsensusMsg, c *Component) {
				// construct a valid basis message signature
				base.Msg.Duty.Type = 1
				base.Msg.Signature = bytes.Repeat([]byte{42}, 65)
				base.Msg.Signature[64] = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}
			},
			func(err error) {
				require.ErrorContains(t, err, "refers to nonexistent peer index, cannot fetch public key")
			},
		},
		{
			"qbft message with justifications mentioning unknown peerIdx errors",
			func(base *pbv1.ConsensusMsg, c *Component) {
				p2pKey := testutil.GenerateInsecureK1Key(t, 0)
				c.pubkeys = make(map[int64]*k1.PublicKey)
				c.pubkeys[0] = p2pKey.PubKey()

				base.Msg.Duty.Type = 1
				base.Msg.PeerIdx = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the base message
				msgHash, err := hashProto(base.Msg)
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					randomMsg(t),
				}

				base.Justification[0].PeerIdx = 42
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the justification
				justHash, err := hashProto(base.Justification[0])
				require.NoError(t, err)

				justSign, err := k1util.Sign(p2pKey, justHash[:])
				require.NoError(t, err)

				base.Justification[0].Signature = justSign
			},
			func(err error) {
				require.ErrorContains(t, err, "refers to nonexistent peer index, cannot fetch public key")
			},
		},
		{
			"qbft message with nil justification present in slice",
			func(base *pbv1.ConsensusMsg, c *Component) {
				p2pKey := testutil.GenerateInsecureK1Key(t, 0)
				c.pubkeys = make(map[int64]*k1.PublicKey)
				c.pubkeys[0] = p2pKey.PubKey()

				base.Msg.Duty.Type = 1
				base.Msg.PeerIdx = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the base message
				msgHash, err := hashProto(base.Msg)
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct nil justifications
				base.Justification = []*pbv1.QBFTMsg{
					nil,
					nil,
				}
			},
			func(err error) {
				require.ErrorContains(t, err, "nil justification")
			},
		},
		{
			"qbft message values present but nil",
			func(base *pbv1.ConsensusMsg, c *Component) {
				p2pKey := testutil.GenerateInsecureK1Key(t, 0)
				c.pubkeys = make(map[int64]*k1.PublicKey)
				c.pubkeys[0] = p2pKey.PubKey()

				// construct a valid basis message signature
				base.Msg.Duty.Type = 1
				base.Msg.PeerIdx = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				base.Values = []*anypb.Any{
					nil,
					nil,
				}

				// Sign the base message
				msgHash, err := hashProto(base.Msg)
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign
			},
			func(err error) {
				require.ErrorContains(t, err, "unmarshal any")
			},
		},
		{
			"qbft message with invalid duty fails",
			func(base *pbv1.ConsensusMsg, c *Component) {
				// construct a valid basis message signature
				base.Msg.Duty.Type = 1
				base.Msg.Signature = bytes.Repeat([]byte{42}, 65)
				base.Msg.Signature[64] = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 0,
				}
			},
			func(err error) {
				require.ErrorContains(t, err, "invalid consensus message duty type")
			},
		},
		{
			"qbft message with valid duty fails because justification has different duty type",
			func(base *pbv1.ConsensusMsg, c *Component) {
				p2pKey := testutil.GenerateInsecureK1Key(t, 0)
				c.pubkeys = make(map[int64]*k1.PublicKey)
				c.pubkeys[0] = p2pKey.PubKey()

				base.Msg.Duty.Type = 1
				base.Msg.PeerIdx = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the base message
				msgHash, err := hashProto(base.Msg)
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					randomMsg(t),
				}

				base.Justification[0].PeerIdx = 0
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 3,
				}

				// Sign the justification
				justHash, err := hashProto(base.Justification[0])
				require.NoError(t, err)

				justSign, err := k1util.Sign(p2pKey, justHash[:])
				require.NoError(t, err)

				base.Justification[0].Signature = justSign
			},
			func(err error) {
				require.ErrorContains(t, err, "justification duty differs from qbft message duty")
			},
		},
		{
			"qbft message with valid duty and justification with same duty does not fail",
			func(base *pbv1.ConsensusMsg, c *Component) {
				p2pKey := testutil.GenerateInsecureK1Key(t, 0)
				c.pubkeys = make(map[int64]*k1.PublicKey)
				c.pubkeys[0] = p2pKey.PubKey()

				base.Msg.Duty.Type = 1
				base.Msg.PeerIdx = 0
				base.Msg.Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the base message
				msgHash, err := hashProto(base.Msg)
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					randomMsg(t),
				}

				base.Justification[0].PeerIdx = 0
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the justification
				justHash, err := hashProto(base.Justification[0])
				require.NoError(t, err)

				justSign, err := k1util.Sign(p2pKey, justHash[:])
				require.NoError(t, err)

				base.Justification[0].Signature = justSign
			},
			func(err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tc Component

			tc.deadliner = testDeadliner{}
			tc.recvBuffers = make(map[core.Duty]chan msg)

			msg := &pbv1.ConsensusMsg{
				Msg: randomMsg(t),
			}

			test.mutate(msg, &tc)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			require.NotPanics(t, func() {
				_, _, err := tc.handle(ctx, "peerID", msg)
				test.checkErr(err)
			})
		})
	}
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner struct {
	deadlineChan chan core.Duty
}

func (testDeadliner) Add(core.Duty) bool {
	return true
}

func (t testDeadliner) C() <-chan core.Duty {
	return t.deadlineChan
}
