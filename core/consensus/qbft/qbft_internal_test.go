// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"bytes"
	"context"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/instance"
	"github.com/obolnetwork/charon/core/consensus/timer"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	coremocks "github.com/obolnetwork/charon/core/mocks"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestDebugRoundChange -update

func TestDebugRoundChange(t *testing.T) {
	const n = 4

	tests := []struct {
		name   string
		msgs   []qbft.Msg[core.Duty, [32]byte, proto.Message]
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
			msgs: []qbft.Msg[core.Duty, [32]byte, proto.Message]{
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

func (t testMsg) ValueSource() (proto.Message, error) {
	panic("implement me")
}

func (t testMsg) PreparedRound() int64 {
	panic("implement me")
}

func (t testMsg) PreparedValue() [32]byte {
	panic("implement me")
}

func (t testMsg) Justification() []qbft.Msg[core.Duty, [32]byte, proto.Message] {
	panic("implement me")
}

func TestQBFTConsensus_handle(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(base *pbv1.QBFTConsensusMsg, c *Consensus)
		checkErr func(err error)
	}{
		{
			"qbft message with no pubkey errors",
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				require.ErrorContains(t, err, "invalid peer index")
			},
		},
		{
			"qbft message with justifications mentioning unknown peerIdx errors",
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				msgHash, err := hashProto(base.GetMsg())
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					newRandomQBFTMsg(t),
				}

				base.Justification[0].PeerIdx = 42
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the justification
				justHash, err := hashProto(base.GetJustification()[0])
				require.NoError(t, err)

				justSign, err := k1util.Sign(p2pKey, justHash[:])
				require.NoError(t, err)

				base.Justification[0].Signature = justSign
			},
			func(err error) {
				require.ErrorContains(t, err, "invalid justification: invalid peer index")
			},
		},
		{
			"qbft message with nil justification present in slice",
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				msgHash, err := hashProto(base.GetMsg())
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
				require.ErrorContains(t, err, "invalid justification: invalid consensus message")
			},
		},
		{
			"qbft message values present but nil",
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				msgHash, err := hashProto(base.GetMsg())
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
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				msgHash, err := hashProto(base.GetMsg())
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					newRandomQBFTMsg(t),
				}

				base.Justification[0].PeerIdx = 0
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 3,
				}

				// Sign the justification
				justHash, err := hashProto(base.GetJustification()[0])
				require.NoError(t, err)

				justSign, err := k1util.Sign(p2pKey, justHash[:])
				require.NoError(t, err)

				base.Justification[0].Signature = justSign
			},
			func(err error) {
				require.ErrorContains(t, err, "qbft justification duty differs from message duty")
			},
		},
		{
			"qbft message with valid duty and justification with same duty does not fail",
			func(base *pbv1.QBFTConsensusMsg, c *Consensus) {
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
				msgHash, err := hashProto(base.GetMsg())
				require.NoError(t, err)

				sign, err := k1util.Sign(p2pKey, msgHash[:])
				require.NoError(t, err)

				base.Msg.Signature = sign

				// construct a justification
				base.Justification = []*pbv1.QBFTMsg{
					newRandomQBFTMsg(t),
				}

				base.Justification[0].PeerIdx = 0
				base.Justification[0].Duty = &pbv1.Duty{
					Slot: 42,
					Type: 1,
				}

				// Sign the justification
				justHash, err := hashProto(base.GetJustification()[0])
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

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tc Consensus

			deadliner := coremocks.NewDeadliner(t)
			deadliner.On("Add", mock.Anything).Maybe().Return(true)
			tc.deadliner = deadliner
			tc.mutable.instances = make(map[core.Duty]*instance.IO[Msg])
			tc.gaterFunc = func(core.Duty) bool { return true }

			msg := &pbv1.QBFTConsensusMsg{
				Msg: newRandomQBFTMsg(t),
			}

			test.mutate(msg, &tc)

			_, _, err := tc.handle(ctx, "peerID", msg)
			test.checkErr(err)
		})
	}
}

func TestQBFTConsensusHandle(t *testing.T) {
	tests := []struct {
		name     string
		msg      *pbv1.QBFTConsensusMsg
		errorMsg string
		peerID   string
	}{
		{
			name:     "invalid message",
			errorMsg: "invalid consensus message",
		},
		{
			name: "nil msg",
			msg: &pbv1.QBFTConsensusMsg{
				Msg: nil,
			},
			errorMsg: "invalid consensus message",
		},
		{
			name: "nil msg duty",
			msg: &pbv1.QBFTConsensusMsg{
				Msg: &pbv1.QBFTMsg{
					Duty: nil,
				},
			},
			errorMsg: "invalid consensus message",
		},
		{
			name: "invalid consensus msg type",
			msg: &pbv1.QBFTConsensusMsg{
				Msg: &pbv1.QBFTMsg{
					Duty: &pbv1.Duty{},
				},
			},
			errorMsg: "invalid consensus message type",
		},
		{
			name: "invalid msg duty type",
			msg: &pbv1.QBFTConsensusMsg{
				Msg: &pbv1.QBFTMsg{
					Duty: &pbv1.Duty{},
					Type: int64(qbft.MsgPrepare),
				},
			},
			errorMsg: "invalid consensus message duty type",
		},
		{
			name: "invalid peer index",
			msg: &pbv1.QBFTConsensusMsg{
				Msg: &pbv1.QBFTMsg{
					Round: 1,
					Duty:  &pbv1.Duty{Type: int32(core.DutyProposer)},
					Type:  int64(qbft.MsgPrepare),
				},
			},
			errorMsg: "invalid peer index",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Consensus{
				gaterFunc: func(core.Duty) bool { return true },
			}

			_, _, err := c.handle(ctx, "", tt.msg)
			require.ErrorContains(t, err, tt.errorMsg)
		})
	}
}

func TestInstanceIO_MaybeStart(t *testing.T) {
	t.Run("MaybeStart for new instance", func(t *testing.T) {
		inst1 := instance.NewIO[Msg]()
		require.True(t, inst1.MaybeStart())
		require.False(t, inst1.MaybeStart())
	})

	t.Run("MaybeStart after handle", func(t *testing.T) {
		var c Consensus

		deadliner := coremocks.NewDeadliner(t)
		deadliner.On("Add", mock.Anything).Return(true)
		c.deadliner = deadliner
		c.gaterFunc = func(core.Duty) bool { return true }
		c.mutable.instances = make(map[core.Duty]*instance.IO[Msg])

		// Generate a p2p private key.
		p2pKey := testutil.GenerateInsecureK1Key(t, 0)
		c.pubkeys = make(map[int64]*k1.PublicKey)
		c.pubkeys[0] = p2pKey.PubKey()

		duty := core.Duty{Slot: 42, Type: 1}
		msg := &pbv1.QBFTConsensusMsg{
			Msg: newRandomQBFTMsg(t),
		}
		msg = signConsensusMsg(t, msg, p2pKey, duty)

		// It should create new instance of instanceIO for the given duty.
		_, _, err := c.handle(context.Background(), "peerID", msg)
		require.NoError(t, err)

		inst, ok := c.mutable.instances[duty]
		require.True(t, ok)
		require.True(t, inst.MaybeStart())
		require.False(t, inst.MaybeStart())
	})

	t.Run("Call Propose after handle", func(t *testing.T) {
		ctx := context.Background()

		var c Consensus

		deadliner := coremocks.NewDeadliner(t)
		deadliner.On("Add", mock.Anything).Return(true)
		c.deadliner = deadliner
		c.gaterFunc = func(core.Duty) bool { return true }
		c.mutable.instances = make(map[core.Duty]*instance.IO[Msg])
		c.timerFunc = timer.GetRoundTimerFunc()

		// Generate a p2p private key pair.
		p2pKey := testutil.GenerateInsecureK1Key(t, 0)
		c.pubkeys = make(map[int64]*k1.PublicKey)
		c.pubkeys[0] = p2pKey.PubKey()
		c.p2pNode = testutil.CreateHost(t, testutil.AvailableAddr(t))

		duty := core.Duty{Slot: 42, Type: 1}
		msg := &pbv1.QBFTConsensusMsg{
			Msg: newRandomQBFTMsg(t),
		}
		msg = signConsensusMsg(t, msg, p2pKey, duty)

		// It should create new instance of instanceIO for the given duty.
		_, _, err := c.handle(ctx, "peerID", msg)
		require.NoError(t, err)

		pubkey := testutil.RandomCorePubKey(t)

		// Propose should internally mark instance as running by calling inst.MaybeStart().
		err = c.Propose(ctx, duty, core.UnsignedDataSet{pubkey: testutil.RandomCoreAttestationData(t)})
		require.Error(t, err) // It should return an error as no peers are specified.

		// Check if MaybeStart is called before.
		inst, ok := c.mutable.instances[duty]
		require.True(t, ok)
		require.False(t, inst.MaybeStart())
	})
}

func signConsensusMsg(t *testing.T, msg *pbv1.QBFTConsensusMsg, privKey *k1.PrivateKey, duty core.Duty) *pbv1.QBFTConsensusMsg {
	t.Helper()

	msg.Msg.Duty.Type = int32(duty.Type)
	msg.Msg.PeerIdx = 0
	msg.Msg.Duty = &pbv1.Duty{
		Slot: duty.Slot,
		Type: int32(duty.Type),
	}

	// Sign the base message
	msgHash, err := hashProto(msg.GetMsg())
	require.NoError(t, err)

	sign, err := k1util.Sign(privKey, msgHash[:])
	require.NoError(t, err)

	msg.Msg.Signature = sign

	// construct a justification
	msg.Justification = []*pbv1.QBFTMsg{
		newRandomQBFTMsg(t),
	}

	msg.Justification[0].PeerIdx = 0
	msg.Justification[0].Duty = &pbv1.Duty{
		Slot: duty.Slot,
		Type: int32(duty.Type),
	}

	// Sign the justification
	justHash, err := hashProto(msg.GetJustification()[0])
	require.NoError(t, err)

	justSign, err := k1util.Sign(privKey, justHash[:])
	require.NoError(t, err)

	msg.Justification[0].Signature = justSign

	return msg
}

func createPrepareProposerValue(t *testing.T, visiblePeers []uint64) proto.Message {
	t.Helper()

	data := core.PrepareProposerData{
		TargetSlot:   100, // Dummy slot
		VisiblePeers: visiblePeers,
	}

	// Wrap in UnsignedDataSet
	set := core.UnsignedDataSet{
		"0x123": data, // Dummy pubkey
	}

	pb, err := core.UnsignedDataSetToProto(set)
	require.NoError(t, err)

	return pb
}

func TestStoreAndGetParticipation(t *testing.T) {
	c := &Consensus{}
	c.prepareParticipation.data = make(map[uint64][]int64)

	// Store participation for slot 10.
	c.storeParticipation(10, createPrepareProposerValue(t, []uint64{0, 1, 2}))

	// Get participants and verify they are sorted.
	participants := c.getParticipants(10)
	require.Equal(t, []int64{0, 1, 2}, participants)

	// Verify non-existent slot returns nil.
	require.Nil(t, c.getParticipants(5))

	// Store for slot 12, should clean up slot 10 (12 - 10 > 1).
	c.storeParticipation(12, createPrepareProposerValue(t, []uint64{3}))

	// Slot 10 should be cleaned up.
	require.Nil(t, c.getParticipants(10))

	// Slot 12 should exist.
	require.Equal(t, []int64{3}, c.getParticipants(12))
}

func TestLeaderWithParticipation(t *testing.T) {
	c := &Consensus{}
	c.prepareParticipation.data = make(map[uint64][]int64)

	const nodes = 4

	tests := []struct {
		name         string
		duty         core.Duty
		round        int64
		participants []int64 // Stored at slot-1 for DutyProposer.
		expected     int64
	}{
		{
			name:     "non-proposer duty uses normal leader",
			duty:     core.Duty{Slot: 10, Type: core.DutyAttester},
			round:    0,
			expected: leader(core.Duty{Slot: 10, Type: core.DutyAttester}, 0, nodes),
		},
		{
			name:     "proposer without participation uses normal leader",
			duty:     core.Duty{Slot: 10, Type: core.DutyProposer},
			round:    0,
			expected: leader(core.Duty{Slot: 10, Type: core.DutyProposer}, 0, nodes),
		},
		{
			name:         "proposer with participation elects from participants only",
			duty:         core.Duty{Slot: 10, Type: core.DutyProposer},
			round:        0,
			participants: []int64{1, 3}, // Stored at slot 9.
			expected:     3,             // (10 + 1 + 0) % 2 = 1, so participants[1] = 3.
		},
		{
			name:         "proposer with all participants same as normal",
			duty:         core.Duty{Slot: 10, Type: core.DutyProposer},
			round:        0,
			participants: []int64{0, 1, 2, 3},
			expected:     leader(core.Duty{Slot: 10, Type: core.DutyProposer}, 0, nodes),
		},
		{
			name:     "proposer at slot 0 uses normal leader",
			duty:     core.Duty{Slot: 0, Type: core.DutyProposer},
			round:    0,
			expected: leader(core.Duty{Slot: 0, Type: core.DutyProposer}, 0, nodes),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and set up participation data.
			c.prepareParticipation.data = make(map[uint64][]int64)
			if tt.participants != nil && tt.duty.Slot > 0 {
				c.prepareParticipation.data[tt.duty.Slot-1] = tt.participants
			}

			result := c.leaderWithParticipation(tt.duty, tt.round, nodes)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestLeaderWithParticipationConsistency(t *testing.T) {
	// This test verifies that all nodes with the same participation data
	// will elect the same leader - the core consistency guarantee.
	c1 := &Consensus{}
	c1.prepareParticipation.data = make(map[uint64][]int64)

	c2 := &Consensus{}
	c2.prepareParticipation.data = make(map[uint64][]int64)

	// Simulate same participation data on both nodes.
	participants := []int64{0, 2, 3} // Node 1 is offline.
	c1.prepareParticipation.data[9] = participants
	c2.prepareParticipation.data[9] = participants

	duty := core.Duty{Slot: 10, Type: core.DutyProposer}

	// Both nodes should elect the same leader for all rounds.
	for round := int64(0); round < 10; round++ {
		leader1 := c1.leaderWithParticipation(duty, round, 4)
		leader2 := c2.leaderWithParticipation(duty, round, 4)
		require.Equal(t, leader1, leader2, "round %d: leaders should match", round)

		// Leader should be one of the participants.
		require.Contains(t, participants, leader1, "leader should be a participant")
	}
}

func TestPrepareProposerToProposerFlow(t *testing.T) {
	// This test simulates the full flow:
	// 1. DutyPrepareProposer at slot N-1 decides with a subset of peers participating
	// 2. DutyProposer at slot N uses participation data to exclude non-participating peers
	const (
		nodes        = 4
		prepareSlot  = 9
		proposerSlot = 10
		offlinePeer  = int64(1) // Peer 1 is offline/malicious
	)

	c := &Consensus{}
	c.prepareParticipation.data = make(map[uint64][]int64)

	// Store participation from DutyPrepareProposer.
	// Only peers 0, 2, 3 participated (peer 1 was offline).
	c.storeParticipation(prepareSlot, createPrepareProposerValue(t, []uint64{0, 2, 3}))

	// Verify participation was stored correctly.
	participants := c.getParticipants(prepareSlot)
	require.Equal(t, []int64{0, 2, 3}, participants)
	require.NotContains(t, participants, offlinePeer)

	// Now simulate DutyProposer at slot 10.
	proposerDuty := core.Duty{Slot: proposerSlot, Type: core.DutyProposer}

	// Verify that for multiple rounds, the leader is never the offline peer.
	for r := range 20 {
		round := int64(r)
		leaderIdx := c.leaderWithParticipation(proposerDuty, round, nodes)

		// Leader must be one of the participating peers.
		require.Contains(t, participants, leaderIdx,
			"round %d: leader %d should be a participant", round, leaderIdx)

		// Leader must NOT be the offline peer.
		require.NotEqual(t, offlinePeer, leaderIdx,
			"round %d: leader should not be the offline peer", round)
	}

	// Compare with normal leader election (without participation data).
	// At least some rounds should have different leaders.
	var differenceCount int

	for r := range 20 {
		round := int64(r)
		normalLeader := leader(proposerDuty, round, nodes)
		participationLeader := c.leaderWithParticipation(proposerDuty, round, nodes)

		if normalLeader != participationLeader {
			differenceCount++
		}
	}

	// We expect differences because peer 1 (offline) would be leader in some rounds
	// with normal election but not with participation-based election.
	require.Positive(t, differenceCount, "participation-based election should differ from normal election when a peer is offline")
}

func TestPrepareProposerExpiresAfterTwoSlots(t *testing.T) {
	// This test verifies that participation data expires correctly.
	const nodes = 4

	c := &Consensus{}
	c.prepareParticipation.data = make(map[uint64][]int64)

	// Store participation at slot 9.
	c.storeParticipation(9, createPrepareProposerValue(t, []uint64{0, 2}))

	// At slot 10 (next slot), participation should still be available.
	proposerDuty10 := core.Duty{Slot: 10, Type: core.DutyProposer}
	leaderSlot10 := c.leaderWithParticipation(proposerDuty10, 0, nodes)
	require.Contains(t, []int64{0, 2}, leaderSlot10, "slot 10 should use participation from slot 9")

	// Store new participation at slot 11 (this cleans up slot 9).
	c.storeParticipation(11, createPrepareProposerValue(t, []uint64{1, 3}))

	// Slot 9 data should be cleaned up.
	require.Nil(t, c.getParticipants(9), "slot 9 data should be expired")

	// Slot 11 data should exist.
	require.Equal(t, []int64{1, 3}, c.getParticipants(11))

	// DutyProposer at slot 12 should use participation from slot 11.
	proposerDuty12 := core.Duty{Slot: 12, Type: core.DutyProposer}
	leaderSlot12 := c.leaderWithParticipation(proposerDuty12, 0, nodes)
	require.Contains(t, []int64{1, 3}, leaderSlot12, "slot 12 should use participation from slot 11")

	// DutyProposer at slot 10 should now fall back to normal election
	// because slot 9 data was cleaned up.
	leaderSlot10After := c.leaderWithParticipation(proposerDuty10, 0, nodes)
	normalLeader := leader(proposerDuty10, 0, nodes)
	require.Equal(t, normalLeader, leaderSlot10After,
		"slot 10 should fall back to normal election after slot 9 data expired")
}
