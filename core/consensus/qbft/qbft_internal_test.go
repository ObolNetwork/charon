// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/instance"
	"github.com/obolnetwork/charon/core/consensus/metrics"
	"github.com/obolnetwork/charon/core/consensus/timer"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	coremocks "github.com/obolnetwork/charon/core/mocks"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
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

func TestIsInsufficientRoundChanges(t *testing.T) {
	const n = 4

	tests := []struct {
		name     string
		msgs     []qbft.Msg[core.Duty, [32]byte, proto.Message]
		round    int64
		quorum   int
		expected bool
	}{
		{
			name:     "round 1 always false",
			round:    1,
			quorum:   3,
			expected: false,
		},
		{
			name: "round 2 with quorum",
			msgs: []qbft.Msg[core.Duty, [32]byte, proto.Message]{
				m(0, qbft.MsgRoundChange),
				m(1, qbft.MsgRoundChange),
				m(2, qbft.MsgRoundChange),
			},
			round:    2,
			quorum:   3,
			expected: false,
		},
		{
			name: "round 2 without quorum",
			msgs: []qbft.Msg[core.Duty, [32]byte, proto.Message]{
				m(0, qbft.MsgRoundChange),
				m(1, qbft.MsgRoundChange),
			},
			round:    2,
			quorum:   3,
			expected: true,
		},
		{
			name:     "round 2 with no messages",
			round:    2,
			quorum:   3,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			steps := groupRoundMessages(test.msgs, n, test.round, 0)
			result := isInsufficientRoundChanges(steps, test.round, test.quorum)
			require.Equal(t, test.expected, result)
		})
	}
}

// TestInsufficientRoundChangesMetric tests the two metric outcomes for insufficient round changes:
//   - outcome="decided": round timed out with insufficient round changes, but the node
//     recovered via MsgDecided from a peer that already decided.
//   - outcome="timeout": round timed out with insufficient round changes, and consensus
//     timed out entirely without ever receiving MsgDecided.
//
// This targets the scenario from https://github.com/ObolNetwork/charon/issues/4478:
// a locally-built block payload arrives late, the leader propagates it to only a subset
// of peers, those peers proceed through QBFT and decide, while the remaining peers
// (including ours) time out with insufficient round changes.
func TestInsufficientRoundChangesMetric(t *testing.T) {
	const nodes = 4

	quorum := qbft.Definition[core.Duty, [32]byte, proto.Message]{Nodes: nodes}.Quorum()

	roundMsgs := func(roundChangeSources ...int64) []qbft.Msg[core.Duty, [32]byte, proto.Message] {
		var msgs []qbft.Msg[core.Duty, [32]byte, proto.Message]
		for _, src := range roundChangeSources {
			msgs = append(msgs, m(src, qbft.MsgRoundChange))
		}

		return msgs
	}

	// simulateInstance mirrors the LogRoundChange wrapper and post-run timeout logic in runInstance.
	// It returns:
	//   - onRoundChange: simulates LogRoundChange callback invocations during qbft.Run
	//   - onTimeout: simulates the post-run timeout path (called when !decided)
	//   - outcomes: returns the list of metric outcomes emitted ("decided" and/or "timeout")
	simulateInstance := func() (
		onRoundChange func(uponRule qbft.UponRule, round int64, msgs []qbft.Msg[core.Duty, [32]byte, proto.Message]),
		onTimeout func(),
		outcomes func() []string,
	) {
		var (
			hadInsufficientRoundChanges bool
			emittedOutcomes             []string
		)

		return func(uponRule qbft.UponRule, round int64, msgs []qbft.Msg[core.Duty, [32]byte, proto.Message]) {
				if uponRule == qbft.UponRoundTimeout {
					steps := groupRoundMessages(msgs, nodes, round, int(leader(core.Duty{Slot: 1, Type: core.DutyAttester}, round, nodes)))
					if isInsufficientRoundChanges(steps, round, quorum) {
						hadInsufficientRoundChanges = true
					}
				}

				if uponRule == qbft.UponJustifiedDecided {
					steps := groupRoundMessages(msgs, nodes, round, int(leader(core.Duty{Slot: 1, Type: core.DutyAttester}, round, nodes)))
					if hadInsufficientRoundChanges || isInsufficientRoundChanges(steps, round, quorum) {
						emittedOutcomes = append(emittedOutcomes, metrics.OutcomeDecided)
					}
				}
			}, func() {
				if hadInsufficientRoundChanges {
					emittedOutcomes = append(emittedOutcomes, metrics.OutcomeTimeout)
				}
			}, func() []string {
				return emittedOutcomes
			}
	}

	t.Run("issue 4478: insufficient round changes then decided via MsgDecided", func(t *testing.T) {
		// Scenario: 4 nodes, our node (peer 3) times out in round 1, moves to round 2.
		// Only peer 3 sends a RoundChange (peers 0,1,2 decided in round 1).
		// MsgDecided arrives before round 2 times out.
		//
		// In production, LogRoundChange receives round=oldRound, so the round 1
		// timeout callback gets round=1. The UponJustifiedDecided callback gets
		// round=2 (current round) with round 2's messages (containing only our
		// own MsgRoundChange).
		onRoundChange, _, outcomes := simulateInstance()

		// Round 1 timeout: LogRoundChange(round=1, newRound=2, UponRoundTimeout).
		// isInsufficientRoundChanges returns false for round 1 (no round changes expected).
		onRoundChange(qbft.UponRoundTimeout, 1, nil)
		require.Empty(t, outcomes(), "no metric for round 1 timeout")

		// MsgDecided arrives while in round 2: LogRoundChange(round=2, UponJustifiedDecided).
		// Round 2 messages contain only our own MsgRoundChange — insufficient.
		onRoundChange(qbft.UponJustifiedDecided, 2, roundMsgs(3))
		require.Equal(t, []string{metrics.OutcomeDecided}, outcomes())
	})

	t.Run("bad network: insufficient round changes and full timeout", func(t *testing.T) {
		// Scenario: our node times out due to a bad network connection.
		// Nobody decided — consensus times out entirely.
		onRoundChange, onTimeout, outcomes := simulateInstance()

		// Round 1 timeout: LogRoundChange(round=1). No flag set (round 1).
		onRoundChange(qbft.UponRoundTimeout, 1, nil)
		require.Empty(t, outcomes())

		// Round 2 timeout: LogRoundChange(round=2). Only our RoundChange — insufficient.
		onRoundChange(qbft.UponRoundTimeout, 2, roundMsgs(3))
		require.Empty(t, outcomes())

		// Consensus times out entirely — timeout outcome emitted.
		onTimeout()
		require.Equal(t, []string{metrics.OutcomeTimeout}, outcomes())
	})

	t.Run("normal round change: sufficient round changes then decided via MsgDecided", func(t *testing.T) {
		// Scenario: round change happens normally with enough peers participating.
		// Even if we later get a MsgDecided, no metric should fire.
		onRoundChange, _, outcomes := simulateInstance()

		// Round 2 timeout: LogRoundChange(round=2). Quorum round changes (3 out of 4).
		onRoundChange(qbft.UponRoundTimeout, 2, roundMsgs(0, 1, 3))
		require.Empty(t, outcomes())

		// MsgDecided arrives while in round 3. Round 3 messages also have sufficient round changes.
		onRoundChange(qbft.UponJustifiedDecided, 3, roundMsgs(0, 1, 3))
		require.Empty(t, outcomes(), "no metric when round changes were sufficient")
	})

	t.Run("normal round change: sufficient round changes then full timeout", func(t *testing.T) {
		// Scenario: round changes were sufficient but consensus still times out
		// (e.g., stuck at prepare/commit phase). No insufficient round changes metric.
		onRoundChange, onTimeout, outcomes := simulateInstance()

		// Round 2 timeout: LogRoundChange(round=2). Quorum round changes.
		onRoundChange(qbft.UponRoundTimeout, 2, roundMsgs(0, 1, 3))
		onTimeout()
		require.Empty(t, outcomes(), "no metric when round changes were sufficient")
	})

	t.Run("normal consensus: decided via commits without any round changes", func(t *testing.T) {
		// Happy path — consensus completes in round 1 via quorum commits.
		onRoundChange, _, outcomes := simulateInstance()

		onRoundChange(qbft.UponQuorumCommits, 1, nil)
		require.Empty(t, outcomes(), "no metric on normal consensus")
	})

	t.Run("round 1 timeout does not trigger flag", func(t *testing.T) {
		// Round 1 timeouts don't check for round changes (round changes are only
		// relevant for rounds > 1). Neither decided nor timeout outcome should fire.
		onRoundChange, onTimeout, outcomes := simulateInstance()

		onRoundChange(qbft.UponRoundTimeout, 1, nil)
		onRoundChange(qbft.UponJustifiedDecided, 1, nil)
		require.Empty(t, outcomes(), "no decided metric for round 1 timeout")

		onTimeout()
		require.Empty(t, outcomes(), "no timeout metric for round 1 timeout")
	})

	t.Run("multiple insufficient rounds then decided", func(t *testing.T) {
		// Multiple rounds time out with insufficient round changes
		// before finally receiving MsgDecided. Decided outcome fires once.
		onRoundChange, _, outcomes := simulateInstance()

		// Round 2 and 3 timeout with insufficient round changes.
		onRoundChange(qbft.UponRoundTimeout, 2, roundMsgs(3))
		onRoundChange(qbft.UponRoundTimeout, 3, roundMsgs(3))
		require.Empty(t, outcomes())

		// MsgDecided arrives while in round 4.
		onRoundChange(qbft.UponJustifiedDecided, 4, roundMsgs(3))
		require.Equal(t, []string{metrics.OutcomeDecided}, outcomes())
	})

	t.Run("multiple insufficient rounds then full timeout", func(t *testing.T) {
		// Multiple rounds time out with insufficient round changes,
		// then consensus times out entirely. Timeout outcome fires once.
		onRoundChange, onTimeout, outcomes := simulateInstance()

		onRoundChange(qbft.UponRoundTimeout, 2, roundMsgs(3))
		onRoundChange(qbft.UponRoundTimeout, 3, roundMsgs(3))
		onRoundChange(qbft.UponRoundTimeout, 4, roundMsgs(3))
		require.Empty(t, outcomes())

		onTimeout()
		require.Equal(t, []string{metrics.OutcomeTimeout}, outcomes())
	})
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
			deadliner.On("Add", mock.Anything).Maybe().Return(core.DeadlineScheduled)
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

// TestQBFTConsensusHandleAmplificationLimits verifies that handle rejects messages
// carrying more justifications or values than a legitimate consensus message ever
// needs, before doing the expensive per-element signature recovery / unmarshalling.
// This caps the CPU/memory amplification a single authenticated peer can inflict.
func TestQBFTConsensusHandleAmplificationLimits(t *testing.T) {
	// newConsensus returns a single-node consensus, so max justifications = 2*nodes = 2.
	newConsensus := func(t *testing.T) (*Consensus, *k1.PrivateKey) {
		t.Helper()

		var c Consensus

		deadliner := coremocks.NewDeadliner(t)
		deadliner.On("Add", mock.Anything).Maybe().Return(core.DeadlineScheduled)
		c.deadliner = deadliner
		c.gaterFunc = func(core.Duty) bool { return true }
		c.mutable.instances = make(map[core.Duty]*instance.IO[Msg])

		p2pKey := testutil.GenerateInsecureK1Key(t, 0)
		c.pubkeys = make(map[int64]*k1.PublicKey)
		c.pubkeys[0] = p2pKey.PubKey()

		return &c, p2pKey
	}

	// signedBase returns a validly-signed main message so verification reaches the limit checks.
	signedBase := func(t *testing.T, p2pKey *k1.PrivateKey) *pbv1.QBFTConsensusMsg {
		t.Helper()

		base := &pbv1.QBFTConsensusMsg{Msg: newRandomQBFTMsg(t)}
		base.Msg.PeerIdx = 0
		base.Msg.Round = 1
		base.Msg.Duty = &pbv1.Duty{Slot: 42, Type: 1}

		msgHash, err := hashProto(base.GetMsg())
		require.NoError(t, err)

		sign, err := k1util.Sign(p2pKey, msgHash[:])
		require.NoError(t, err)

		base.Msg.Signature = sign

		return base
	}

	// signedJustification returns a validly-signed justification matching the base message's duty.
	signedJustification := func(t *testing.T, p2pKey *k1.PrivateKey) *pbv1.QBFTMsg {
		t.Helper()

		j := newRandomQBFTMsg(t)
		j.PeerIdx = 0
		j.Round = 1 // verifyMsg requires round > 0, don't rely on the random value.
		j.Duty = &pbv1.Duty{Slot: 42, Type: 1}

		jHash, err := hashProto(j)
		require.NoError(t, err)

		j.Signature, err = k1util.Sign(p2pKey, jHash[:])
		require.NoError(t, err)

		return j
	}

	t.Run("too many justifications rejected", func(t *testing.T) {
		c, p2pKey := newConsensus(t)
		base := signedBase(t, p2pKey)

		// 3 justifications > 2*nodes (2). Content is irrelevant since the count
		// check runs before any per-justification verification.
		for range 3 {
			base.Justification = append(base.Justification, &pbv1.QBFTMsg{})
		}

		_, _, err := c.handle(context.Background(), "peerID", base)
		require.ErrorContains(t, err, "too many justifications")
	})

	t.Run("max justifications accepted", func(t *testing.T) {
		c, p2pKey := newConsensus(t)
		base := signedBase(t, p2pKey)

		// Exactly 2*nodes (2) justifications must not be rejected by the count check.
		for range 2 {
			base.Justification = append(base.Justification, signedJustification(t, p2pKey))
		}

		_, _, err := c.handle(context.Background(), "peerID", base)
		require.NoError(t, err)
	})

	t.Run("too many values rejected", func(t *testing.T) {
		c, p2pKey := newConsensus(t)
		base := signedBase(t, p2pKey)

		// 0 justifications => max values = 2*(0+1) = 2. Provide 3.
		base.Values = []*anypb.Any{{}, {}, {}}

		_, _, err := c.handle(context.Background(), "peerID", base)
		require.ErrorContains(t, err, "too many values")
	})

	t.Run("max values accepted", func(t *testing.T) {
		c, p2pKey := newConsensus(t)
		base := signedBase(t, p2pKey)

		// 2 justifications => max values = 2*(2+1) = 6. A message carrying exactly
		// the maximum must pass the count check and the rest of handle, guarding
		// against the bound being tightened below the legitimate maximum.
		for range 2 {
			base.Justification = append(base.Justification, signedJustification(t, p2pKey))
		}

		for i := range 6 {
			value, err := anypb.New(&pbv1.Duty{Slot: uint64(i + 1)})
			require.NoError(t, err)

			base.Values = append(base.Values, value)
		}

		_, _, err := c.handle(context.Background(), "peerID", base)
		require.NoError(t, err)
	})
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
		deadliner.On("Add", mock.Anything).Return(core.DeadlineScheduled)
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
		deadliner.On("Add", mock.Anything).Return(core.DeadlineScheduled)
		c.deadliner = deadliner
		c.gaterFunc = func(core.Duty) bool { return true }
		c.mutable.instances = make(map[core.Duty]*instance.IO[Msg])
		// Use zero values for tests to use default clock.Now() behavior
		c.timerFunc = timer.GetRoundTimerFunc(time.Time{}, 0, func(core.Duty) time.Duration { return 0 })

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

// TestDecidedMessageScenarios verifies how a node handles crafted MsgDecided messages:
//
//   - A justification containing extra non-matching COMMITs must not influence the
//     decided value or crash the node. The Decide callback must use the algorithm's
//     agreed value parameter, not qcommit[0], so an attacker-controlled COMMIT at
//     index 0 is harmless.
//   - The decided value must come from the quorum, never from the node's own
//     (differing) local proposal.
//   - Malformed decided messages (missing values, unjustified round or quorum) must
//     be rejected or dropped without corrupting the instance: a subsequent valid
//     decided message must still decide the agreed value.
//
// All scenarios run both with and without attestation comparison (the
// chain_split_halt feature): the Compare flow only gates the PREPARE step on
// justified PRE-PREPAREs and must not affect decided message handling.
func TestDecidedMessageScenarios(t *testing.T) {
	t.Run("compare disabled", func(t *testing.T) {
		testDecidedMessageScenarios(t, false)
	})
	t.Run("compare enabled", func(t *testing.T) {
		testDecidedMessageScenarios(t, true)
	})
}

func testDecidedMessageScenarios(t *testing.T, compareAttestations bool) {
	t.Helper()

	const (
		nodes    = 4
		slot     = 2
		attacker = 3
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, 3, nodes, 0, random)

	var peers []p2p.Peer

	for i := range nodes {
		record, err := enr.Parse(lock.Operators[i].ENR)
		require.NoError(t, err)

		p, err := p2p.NewPeerFromENR(record, i)
		require.NoError(t, err)

		peers = append(peers, p)
	}

	addr := testutil.AvailableAddr(t)
	mAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
	require.NoError(t, err)

	priv := (*libp2pcrypto.Secp256k1PrivateKey)(p2pkeys[0])
	h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrs(mAddr))
	testutil.SkipIfBindErr(t, err)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })

	deadliner := coremocks.NewDeadliner(t)
	deadliner.On("Add", mock.Anything).Maybe().Return(core.DeadlineScheduled)
	deadliner.On("C").Maybe().Return((<-chan core.Duty)(make(chan core.Duty)))

	bmock, err := beaconmock.New(t.Context(), beaconmock.WithGenesisTime(time.Time{}))
	require.NoError(t, err)

	c, err := NewConsensus(t.Context(), bmock, h, new(p2p.Sender), peers, p2pkeys[0],
		deadliner, func(core.Duty) bool { return true }, func(*pbv1.SniffedConsensusInstance) {}, compareAttestations)
	require.NoError(t, err)

	results := make(chan core.UnsignedDataSet, 1)

	c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
		results <- set
		return nil
	})
	c.Start(t.Context())

	// Build two distinct values: the legitimately agreed one and a rogue one.
	newValue := func() (*anypb.Any, [32]byte) {
		set := core.UnsignedDataSet{testutil.RandomCorePubKey(t): testutil.RandomCoreAttestationData(t)}
		pb, err2 := core.UnsignedDataSetToProto(set)
		require.NoError(t, err2)

		hash, err2 := hashProto(pb)
		require.NoError(t, err2)

		a, err2 := anypb.New(pb)
		require.NoError(t, err2)

		return a, hash
	}

	signCommit := func(key *k1.PrivateKey, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg {
		m := &pbv1.QBFTMsg{
			Type:      int64(qbft.MsgCommit),
			Duty:      &pbv1.Duty{Slot: slot, Type: int32(core.DutyAttester)},
			PeerIdx:   peerIdx,
			Round:     round,
			ValueHash: valueHash[:],
		}

		signed, err2 := signMsg(m, key)
		require.NoError(t, err2)

		return signed
	}

	agreedAny, agreedHash := newValue()
	rogueAny, rogueHash := newValue()
	localAny, _ := newValue()

	require.NotEqual(t, agreedHash, rogueHash)

	nextSlot := uint64(slot)

	// startInstance proposes the given value on a fresh duty and returns the duty,
	// a per-duty signing function, the propose error channel and a context.
	startInstance := func(t *testing.T, propose *anypb.Any) (
		core.Duty,
		func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg,
		chan error,
		context.Context,
		context.CancelFunc,
	) {
		t.Helper()

		testDuty := core.Duty{Type: core.DutyAttester, Slot: nextSlot}
		nextSlot++

		signForDuty := func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg {
			m := &pbv1.QBFTMsg{
				Type:      int64(typ),
				Duty:      &pbv1.Duty{Slot: testDuty.Slot, Type: int32(core.DutyAttester)},
				PeerIdx:   peerIdx,
				Round:     round,
				ValueHash: valueHash[:],
			}

			signed, err2 := signMsg(m, key)
			require.NoError(t, err2)

			return signed
		}

		proposeSet, err := core.UnsignedDataSetFromProto(core.DutyAttester, mustUnmarshalUDS(t, propose))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)

		proposeErr := make(chan error, 1)
		go func() { proposeErr <- c.Propose(ctx, testDuty, proposeSet) }()

		require.Eventually(t, func() bool {
			return c.getInstanceIO(testDuty).Running.Load()
		}, 5*time.Second, 10*time.Millisecond)

		return testDuty, signForDuty, proposeErr, ctx, cancel
	}

	// expectDecided asserts the subscriber receives the agreed value before the context expires.
	expectDecided := func(t *testing.T, ctx context.Context) {
		t.Helper()

		select {
		case got := <-results:
			gotPb, err := core.UnsignedDataSetToProto(got)
			require.NoError(t, err)

			gotHash, err := hashProto(gotPb)
			require.NoError(t, err)

			require.Equal(t, agreedHash, gotHash, "must decide on the agreed value")
		case <-ctx.Done():
			t.Fatal("timed out — node may have crashed")
		}
	}

	// runSubtest proposes the given value on a fresh duty, injects a crafted MsgDecided
	// with the provided justification, and asserts the victim decides on the agreed value
	// without panicking.
	runSubtest := func(t *testing.T, name string, propose *anypb.Any, justification []*pbv1.QBFTMsg) {
		t.Helper()

		t.Run(name, func(t *testing.T) {
			_, signForDuty, proposeErr, ctx, cancel := startInstance(t, propose)
			defer cancel()

			// Re-sign justification messages with the correct duty slot.
			var resignedJust []*pbv1.QBFTMsg
			for _, j := range justification {
				resignedJust = append(resignedJust, signForDuty(
					p2pkeys[j.GetPeerIdx()],
					qbft.MsgType(j.GetType()),
					j.GetPeerIdx(),
					j.GetRound(),
					[32]byte(j.GetValueHash()),
				))
			}

			decided := &pbv1.QBFTConsensusMsg{
				Msg:           signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 1, agreedHash),
				Justification: resignedJust,
				Values:        []*anypb.Any{agreedAny, rogueAny},
			}

			require.NotPanics(t, func() {
				_, _, err := c.handle(ctx, "attacker", decided)
				require.NoError(t, err)
			})

			expectDecided(t, ctx)

			cancel()
			<-proposeErr
		})
	}

	// runRejectSubtest proposes the agreed value on a fresh duty and injects a bad
	// MsgDecided that must not decide anything: either handle rejects it outright
	// (wantHandleErr) or the qbft instance drops it as unjustified. A subsequent
	// valid MsgDecided must still decide the agreed value, proving the bad message
	// neither decided nor corrupted the instance.
	runRejectSubtest := func(t *testing.T, name, wantHandleErr string,
		buildBad func(signForDuty func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg) *pbv1.QBFTConsensusMsg,
	) {
		t.Helper()

		t.Run(name, func(t *testing.T) {
			_, signForDuty, proposeErr, ctx, cancel := startInstance(t, agreedAny)
			defer cancel()

			require.NotPanics(t, func() {
				_, _, err := c.handle(ctx, "attacker", buildBad(signForDuty))
				if wantHandleErr != "" {
					require.ErrorContains(t, err, wantHandleErr)
				} else {
					require.NoError(t, err)
				}
			})

			good := &pbv1.QBFTConsensusMsg{
				Msg: signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 1, agreedHash),
				Justification: []*pbv1.QBFTMsg{
					signForDuty(p2pkeys[1], qbft.MsgCommit, 1, 1, agreedHash),
					signForDuty(p2pkeys[2], qbft.MsgCommit, 2, 1, agreedHash),
					signForDuty(p2pkeys[attacker], qbft.MsgCommit, attacker, 1, agreedHash),
				},
				Values: []*anypb.Any{agreedAny},
			}

			_, _, err := c.handle(ctx, "attacker", good)
			require.NoError(t, err)

			expectDecided(t, ctx)

			cancel()
			<-proposeErr
		})
	}

	// Template justification messages (slot is overridden by runSubtest).
	honestCommits := []*pbv1.QBFTMsg{
		signCommit(p2pkeys[1], 1, 1, agreedHash),
		signCommit(p2pkeys[2], 2, 1, agreedHash),
		signCommit(p2pkeys[attacker], attacker, 1, agreedHash),
	}

	rogueFirst := append([]*pbv1.QBFTMsg{
		signCommit(p2pkeys[attacker], attacker, 1, rogueHash),
	}, honestCommits...)

	rogueLast := append(append([]*pbv1.QBFTMsg{}, honestCommits...),
		signCommit(p2pkeys[attacker], attacker, 1, rogueHash),
	)

	rogueMiddle := []*pbv1.QBFTMsg{
		signCommit(p2pkeys[1], 1, 1, agreedHash),
		signCommit(p2pkeys[attacker], attacker, 1, rogueHash),
		signCommit(p2pkeys[2], 2, 1, agreedHash),
		signCommit(p2pkeys[attacker], attacker, 1, agreedHash),
	}

	overflowFirst := append([]*pbv1.QBFTMsg{
		signCommit(p2pkeys[attacker], attacker, math.MaxInt64-1, rogueHash),
	}, honestCommits...)

	runSubtest(t, "rogue commit at start", agreedAny, rogueFirst)
	runSubtest(t, "rogue commit at end", agreedAny, rogueLast)
	runSubtest(t, "rogue commit in middle", agreedAny, rogueMiddle)
	runSubtest(t, "overflow round at start", agreedAny, overflowFirst)

	// The node's own (differing) local proposal must never leak into the decision:
	// the subscriber must receive the quorum-agreed value.
	runSubtest(t, "local proposal differs from decided value", localAny, honestCommits)

	runRejectSubtest(t, "decided value missing from values", "value hash not found in values",
		func(signForDuty func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg) *pbv1.QBFTConsensusMsg {
			// The decided message claims the rogue value but does not include it in
			// its values, only the agreed one. Decoding must fail, so the node can
			// never be tricked into deciding a value it does not have.
			return &pbv1.QBFTConsensusMsg{
				Msg: signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 1, rogueHash),
				Justification: []*pbv1.QBFTMsg{
					signForDuty(p2pkeys[1], qbft.MsgCommit, 1, 1, rogueHash),
					signForDuty(p2pkeys[2], qbft.MsgCommit, 2, 1, rogueHash),
					signForDuty(p2pkeys[attacker], qbft.MsgCommit, attacker, 1, rogueHash),
				},
				Values: []*anypb.Any{agreedAny},
			}
		})

	runRejectSubtest(t, "justification value missing from values", "value hash not found in values",
		func(signForDuty func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg) *pbv1.QBFTConsensusMsg {
			// The justification references the rogue value which is absent from values.
			return &pbv1.QBFTConsensusMsg{
				Msg: signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 1, agreedHash),
				Justification: []*pbv1.QBFTMsg{
					signForDuty(p2pkeys[1], qbft.MsgCommit, 1, 1, agreedHash),
					signForDuty(p2pkeys[2], qbft.MsgCommit, 2, 1, agreedHash),
					signForDuty(p2pkeys[attacker], qbft.MsgCommit, attacker, 1, rogueHash),
				},
				Values: []*anypb.Any{agreedAny},
			}
		})

	runRejectSubtest(t, "decided round not matching justification commits", "",
		func(signForDuty func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg) *pbv1.QBFTConsensusMsg {
			// The decided message claims round 2 while all commits are for round 1.
			// The message passes wire validation but must be dropped as unjustified.
			return &pbv1.QBFTConsensusMsg{
				Msg: signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 2, rogueHash),
				Justification: []*pbv1.QBFTMsg{
					signForDuty(p2pkeys[1], qbft.MsgCommit, 1, 1, rogueHash),
					signForDuty(p2pkeys[2], qbft.MsgCommit, 2, 1, rogueHash),
					signForDuty(p2pkeys[attacker], qbft.MsgCommit, attacker, 1, rogueHash),
				},
				Values: []*anypb.Any{agreedAny, rogueAny},
			}
		})

	runRejectSubtest(t, "decided with insufficient justification", "",
		func(signForDuty func(key *k1.PrivateKey, typ qbft.MsgType, peerIdx, round int64, valueHash [32]byte) *pbv1.QBFTMsg) *pbv1.QBFTConsensusMsg {
			// Only two commits back the decided message; quorum is three.
			return &pbv1.QBFTConsensusMsg{
				Msg: signForDuty(p2pkeys[attacker], qbft.MsgDecided, attacker, 1, rogueHash),
				Justification: []*pbv1.QBFTMsg{
					signForDuty(p2pkeys[1], qbft.MsgCommit, 1, 1, rogueHash),
					signForDuty(p2pkeys[attacker], qbft.MsgCommit, attacker, 1, rogueHash),
				},
				Values: []*anypb.Any{agreedAny, rogueAny},
			}
		})
}

func mustUnmarshalUDS(t *testing.T, a *anypb.Any) *pbv1.UnsignedDataSet {
	t.Helper()

	m, err := a.UnmarshalNew()
	require.NoError(t, err)

	set, ok := m.(*pbv1.UnsignedDataSet)
	require.True(t, ok)

	return set
}

// TestAttestationChecker verifies the chain_split_halt comparator: identical
// attestation data passes, any source/target vote mismatch fails, and leader
// validators unknown to the local set are skipped.
func TestAttestationChecker(t *testing.T) {
	pubkey := testutil.RandomCorePubKey(t)
	attData := testutil.RandomCoreAttestationData(t)

	toProto := func(t *testing.T, pk core.PubKey, data core.AttestationData) *pbv1.UnsignedDataSet {
		t.Helper()

		set, err := core.UnsignedDataSetToProto(core.UnsignedDataSet{pk: data})
		require.NoError(t, err)

		return set
	}

	cloneAtt := func(t *testing.T) core.AttestationData {
		t.Helper()

		dup, err := attData.Clone()
		require.NoError(t, err)

		att, ok := dup.(core.AttestationData)
		require.True(t, ok)

		return att
	}

	local := toProto(t, pubkey, attData)

	tests := []struct {
		name    string
		mutate  func(*core.AttestationData)
		wantErr string
	}{
		{
			name: "identical attestation data",
		},
		{
			name:    "source epoch differs",
			mutate:  func(a *core.AttestationData) { a.Data.Source.Epoch++ },
			wantErr: "source epoch differs",
		},
		{
			name:    "source root differs",
			mutate:  func(a *core.AttestationData) { a.Data.Source.Root[0]++ },
			wantErr: "source root differs",
		},
		{
			name:    "target epoch differs",
			mutate:  func(a *core.AttestationData) { a.Data.Target.Epoch++ },
			wantErr: "target epoch differs",
		},
		{
			name:    "target root differs",
			mutate:  func(a *core.AttestationData) { a.Data.Target.Root[0]++ },
			wantErr: "target root differs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaderAtt := cloneAtt(t)
			if test.mutate != nil {
				test.mutate(&leaderAtt)
			}

			err := attestationChecker(t.Context(), toProto(t, pubkey, leaderAtt), local)
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}

	t.Run("unknown validator is skipped", func(t *testing.T) {
		// Leader proposes for a validator the local node has no data for: a
		// conflicting vote cannot be detected, so it is skipped with a warning.
		leaderAtt := cloneAtt(t)
		leaderAtt.Data.Target.Epoch++

		err := attestationChecker(t.Context(), toProto(t, testutil.RandomCorePubKey(t), leaderAtt), local)
		require.NoError(t, err)
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
