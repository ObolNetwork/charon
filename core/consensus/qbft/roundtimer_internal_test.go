// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/featureset"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/timer"
	"github.com/obolnetwork/charon/core/qbft"
)

// TestRoundTimersFirstLeaderDown runs a cluster whose first round leader is down, for each timer users
// can configure with feature flags, verifying the other peers decide in the second round, right after
// the first round times out. It runs in a synctest bubble, where time is fake and only advances once
// all peers are blocked, so it neither waits in real time nor depends on goroutine scheduling.
func TestRoundTimersFirstLeaderDown(t *testing.T) {
	const (
		nodes         = 4
		slot          = 1
		slotsPerEpoch = 32
		slotDuration  = 12 * time.Second
		latency       = 10 * time.Millisecond
		// decideAfter is how long the second round takes to decide after the first round times out:
		// the round changes, then the pre-prepare, prepares and commits, each delayed by the latency.
		decideAfter = 4 * latency
	)

	tests := []struct {
		name     string
		enable   []featureset.Feature
		disable  []featureset.Feature
		dutyType core.DutyType
		gloas    bool // Whether gloas is active at the duty's slot.
		// dutyOffset is the duty's offset into the slot, when it is due.
		dutyOffset time.Duration
		wantType   timer.Type
		// firstRoundEnd is when the first round times out, relative to the start of the slot.
		firstRoundEnd time.Duration
	}{
		{
			name:          "attester, defaults",
			dutyType:      core.DutyAttester,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: time.Second,
		},
		{
			name:          "attester, eager double linear disabled",
			disable:       []featureset.Feature{featureset.EagerDoubleLinear},
			dutyType:      core.DutyAttester,
			wantType:      timer.TimerIncreasing,
			firstRoundEnd: time.Second,
		},
		{
			name:          "gloas attester, defaults",
			dutyType:      core.DutyAttester,
			gloas:         true,
			dutyOffset:    3 * time.Second,
			wantType:      timer.TimerEagerAheadSplit,
			firstRoundEnd: 4 * time.Second,
		},
		{
			name:          "proposer, defaults",
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: 1500 * time.Millisecond,
		},
		{
			name:          "proposer, proposal timeout disabled",
			disable:       []featureset.Feature{featureset.ProposalTimeout},
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerEagerDoubleLinear,
			firstRoundEnd: time.Second,
		},
		{
			name:          "proposer, linear enabled",
			enable:        []featureset.Feature{featureset.Linear},
			dutyType:      core.DutyProposer,
			wantType:      timer.TimerLinear,
			firstRoundEnd: 1500 * time.Millisecond,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, feature := range test.enable {
				featureset.EnableForT(t, feature)
			}

			for _, feature := range test.disable {
				featureset.DisableForT(t, feature)
			}

			synctest.Test(t, func(t *testing.T) {
				// The bubble's fake time starts at the start of the slot.
				slotStart := time.Now()
				genesisTime := slotStart.Add(-slot * slotDuration)
				forkSchedule := func() eth2wrap.ForkForkSchedule {
					if !test.gloas {
						return eth2wrap.ForkForkSchedule{}
					}

					return eth2wrap.ForkForkSchedule{eth2wrap.Gloas: {Epoch: 0}}
				}

				slotOffset := func(core.Duty) time.Duration { return test.dutyOffset }
				timerFunc := timer.GetRoundTimerFunc(genesisTime, slotDuration, slotsPerEpoch, slotOffset, forkSchedule)

				duty := core.Duty{Slot: slot, Type: test.dutyType}
				require.Equal(t, test.wantType, timerFunc(duty).Type())

				firstLeader := leader(duty, 1, nodes)
				transport := newBubbleTransport(latency)

				ctx, cancel := context.WithTimeout(t.Context(), slotDuration)
				defer cancel()

				var (
					wg      sync.WaitGroup
					mu      sync.Mutex
					decided = make(map[int64]result)
				)

				for peer := range int64(nodes) {
					if peer == firstLeader {
						continue // The first leader is down.
					}

					receive := transport.join(peer)

					wg.Go(func() {
						def := newSimDefinition(nodes, timerFunc(duty), func(qcommit []qbft.Msg[core.Duty, [32]byte, proto.Message]) {
							mu.Lock()
							defer mu.Unlock()

							decided[peer] = result{PeerIdx: peer, Decided: true, Round: qcommit[0].Round(), Duration: time.Since(slotStart)}
							if len(decided) == nodes-1 {
								cancel()
							}
						})

						valCh := make(chan [32]byte, 1)
						valCh <- [32]byte{0xFF, byte(peer)}

						qbftTransport := qbft.Transport[core.Duty, [32]byte, proto.Message]{
							Broadcast: transport.broadcast,
							Receive:   receive,
						}

						_ = qbft.Run(ctx, def, qbftTransport, duty, peer, valCh, make(chan proto.Message, 1))
					})
				}

				wg.Wait()

				require.Len(t, decided, nodes-1, "not all online peers decided")

				for peer, res := range decided {
					require.EqualValues(t, 2, res.Round, "peer %d", peer)
					require.Equal(t, test.firstRoundEnd+decideAfter, res.Duration, "peer %d", peer)
				}
			})
		})
	}
}

// bubbleTransport is a QBFT transport for a synctest bubble, delivering messages to peers after a
// latency, measured in the bubble's fake time.
type bubbleTransport struct {
	latency time.Duration

	mu       sync.Mutex
	receives map[int64]chan qbft.Msg[core.Duty, [32]byte, proto.Message]
}

func newBubbleTransport(latency time.Duration) *bubbleTransport {
	return &bubbleTransport{
		latency:  latency,
		receives: make(map[int64]chan qbft.Msg[core.Duty, [32]byte, proto.Message]),
	}
}

// join returns the receive channel of the peer.
func (b *bubbleTransport) join(peer int64) chan qbft.Msg[core.Duty, [32]byte, proto.Message] {
	b.mu.Lock()
	defer b.mu.Unlock()

	receive := make(chan qbft.Msg[core.Duty, [32]byte, proto.Message], 1000)
	b.receives[peer] = receive

	return receive
}

// broadcast delivers the message to the sender immediately, and to the other peers after the latency.
func (b *bubbleTransport) broadcast(_ context.Context, typ qbft.MsgType, duty core.Duty, source int64,
	round int64, value [32]byte, pr int64, pv [32]byte, justification []qbft.Msg[core.Duty, [32]byte, proto.Message],
) error {
	msg, err := newSimMsg(typ, duty, source, round, value, pr, pv, justification)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for peer, receive := range b.receives {
		if peer == source {
			receive <- msg
			continue
		}

		time.AfterFunc(b.latency, func() { receive <- msg })
	}

	return nil
}
