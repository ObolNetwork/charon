// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

const (
	ms050  = time.Millisecond * 50
	ms100  = time.Millisecond * 100
	ms250  = time.Millisecond * 250
	ms500  = time.Millisecond * 500
	ms1000 = time.Millisecond * 1000
	ms2500 = time.Millisecond * 2500
	ms5000 = time.Millisecond * 5000
	min1   = time.Minute * 1
)

var incTimer = func(clock clockwork.Clock) roundTimer {
	timer := newIncreasingRoundTimer()
	timer.clock = clock

	return timer
}

func TestSimulatorOnce(t *testing.T) {
	results := testStrategySimulator(t, ssConfig{
		latencyStdDev: ms050,
		latencyPerPeer: map[int64]time.Duration{
			0: ms100,
			1: ms100,
			2: ms100,
			3: ms100,
		},
		roundTimerFunc: incTimer,
		timeout:        min1,
	})
	require.Equal(t, 4, len(results))
	for _, res := range results {
		require.Equal(t, true, res.Decided)
		require.EqualValues(t, 1, res.Round)
	}
}

// TODO(corver): add a benchmark-type test that calculates a "score" for a round timer
//  across a range of parameters and compares that with other round timers.

// peerID is a peer identifier of which the zero value is invalid.
type peerID struct {
	Idx int64
	OK  bool
}

type ssConfig struct {
	seed           int
	latencyStdDev  time.Duration
	latencyPerPeer map[int64]time.Duration
	startByPeer    map[int64]time.Duration
	roundTimerFunc func(clockwork.Clock) roundTimer
	timeout        time.Duration
}

func testStrategySimulator(t *testing.T, conf ssConfig) []result {
	t.Helper()
	random := rand.New(rand.NewSource(int64(conf.seed)))
	clock := clockwork.NewFakeClock()
	since := sinceMSFunc(clock)
	txSimulator := newTransportSimulator(clock, random, conf.latencyStdDev, conf.latencyPerPeer)

	var (
		peerIDs    []peerID
		transports []qbft.Transport[core.Duty, [32]byte]
	)
	for peerIdx := range conf.latencyPerPeer {
		peerIDs = append(peerIDs, peerID{Idx: peerIdx, OK: true})
		transports = append(transports, txSimulator.instance(peerIdx))
	}

	work := func(ctx context.Context, p peerID) (result, error) {
		res := result{PeerIdx: p.Idx, Decided: false}
		def := newSimDefinition(
			len(conf.latencyPerPeer),
			conf.roundTimerFunc(clock),
			func(qcommit []qbft.Msg[core.Duty, [32]byte]) {
				res = result{
					PeerIdx:    p.Idx,
					Decided:    true,
					Round:      qcommit[0].Round(),
					DurationMS: since(),
				}
			},
		)

		// Unique non-zero value per peer
		var val [32]byte
		val[0], val[1] = byte(0xFF), byte(p.Idx)

		// Delay start of peer
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-clock.After(conf.startByPeer[p.Idx]):
		}

		err := qbft.Run(ctx, def, transports[p.Idx], core.Duty{}, p.Idx, val)
		if errors.Is(err, context.Canceled) {
			return res, nil
		}

		return res, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fjResults, fjCancel := forkjoin.NewWithInputs(ctx, work, peerIDs)
	defer fjCancel()

	// Run the simulator until timeout.
	go func() {
		t0 := clock.Now()
		for {
			time.Sleep(time.Microsecond)
			clock.Advance(time.Millisecond * 10)
			txSimulator.processBuffer()
			if clock.Since(t0) < conf.timeout {
				time.Sleep(time.Microsecond)
				continue
			}

			cancel() // Cancel the context to stop consensus.

			return
		}
	}()

	results, err := fjResults.Flatten()
	if err != nil {
		require.Fail(t, "unexpected error", err)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].PeerIdx < results[j].PeerIdx
	})

	return results
}

func newSimDefinition(nodes int, roundTimer roundTimer, decideCallback func(qcommit []qbft.Msg[core.Duty, [32]byte])) qbft.Definition[core.Duty, [32]byte] {
	return qbft.Definition[core.Duty, [32]byte]{
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, nodes) == process
		},
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			decideCallback(qcommit)
		},
		NewTimer:  roundTimer.Timer,
		LogUnjust: func(context.Context, core.Duty, int64, qbft.Msg[core.Duty, [32]byte]) {},
		LogRoundChange: func(context.Context, core.Duty, int64, int64, int64, qbft.UponRule, []qbft.Msg[core.Duty, [32]byte]) {
		},
		LogUponRule: func(context.Context, core.Duty, int64, int64, qbft.Msg[core.Duty, [32]byte], qbft.UponRule) {},
		// Nodes is the number of nodes.
		Nodes: nodes,

		// FIFOLimit caps the max buffered messages per peer.
		FIFOLimit: recvBuffer,
	}
}

type result struct {
	PeerIdx    int64
	Decided    bool
	Round      int64
	DurationMS int64
}

type tuple struct {
	Msg    qbft.Msg[core.Duty, [32]byte]
	To     int64
	Arrive time.Time
}

func newTransportSimulator(clock clockwork.Clock, random *rand.Rand, latencyStdDev time.Duration,
	latencyPerPeer map[int64]time.Duration,
) *transportSimulator {
	return &transportSimulator{
		clock:          clock,
		random:         random,
		latencyStdDev:  latencyStdDev,
		latencyPerPeer: latencyPerPeer,
		instances:      make(map[int64]*transportInstance),
	}
}

type transportSimulator struct {
	clock          clockwork.Clock
	random         *rand.Rand
	latencyStdDev  time.Duration
	latencyPerPeer map[int64]time.Duration

	mu        sync.Mutex
	buffer    []tuple
	instances map[int64]*transportInstance
}

func (s *transportSimulator) enqueue(msg qbft.Msg[core.Duty, [32]byte]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	for to, mean := range s.latencyPerPeer {
		latency := randomNormDuration(mean, s.latencyStdDev, s.random)
		if to == msg.Source() {
			latency = 0
		}

		s.buffer = append(s.buffer, tuple{
			Msg:    msg,
			To:     to,
			Arrive: now.Add(latency),
		})
	}
}

func (s *transportSimulator) processBuffer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buffer) == 0 {
		return
	}

	now := s.clock.Now()
	var remaining []tuple
	for _, tuple := range s.buffer {
		if tuple.Arrive.After(now) {
			remaining = append(remaining, tuple)
			continue
		}

		select {
		case s.instances[tuple.To].receive <- tuple.Msg:
		default:
			panic("bug: receive buffer full")
		}
	}

	s.buffer = remaining
}

func (s *transportSimulator) instance(peerIdx int64) qbft.Transport[core.Duty, [32]byte] {
	s.mu.Lock()
	defer s.mu.Unlock()

	inst, ok := s.instances[peerIdx]
	if !ok {
		inst = &transportInstance{
			transportSimulator: s,
			peerIdx:            peerIdx,
			receive:            make(chan qbft.Msg[core.Duty, [32]byte], 1000),
		}
		s.instances[peerIdx] = inst
	}

	return qbft.Transport[core.Duty, [32]byte]{
		Broadcast: inst.Broadcast,
		Receive:   inst.Receive(),
	}
}

type transportInstance struct {
	*transportSimulator
	peerIdx int64
	receive chan qbft.Msg[core.Duty, [32]byte]
}

func (i *transportInstance) Broadcast(_ context.Context, typ qbft.MsgType,
	duty core.Duty, source int64, round int64, value [32]byte,
	pr int64, pv [32]byte, justification []qbft.Msg[core.Duty, [32]byte],
) error {
	dummy, _ := anypb.New(timestamppb.Now())
	values := map[[32]byte]*anypb.Any{
		value: dummy,
		pv:    dummy,
	}

	pbMsg := &pbv1.QBFTMsg{
		Type:              int64(typ),
		Duty:              core.DutyToProto(duty),
		PeerIdx:           source,
		Round:             round,
		ValueHash:         value[:],
		PreparedRound:     pr,
		PreparedValueHash: pv[:],
	}

	// Transform justifications into protobufs
	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(msg)
		if !ok {
			return errors.New("invalid justification")
		}
		justMsgs = append(justMsgs, impl.msg) // Note nested justifications are ignored.
	}

	msg, err := newMsg(pbMsg, justMsgs, values)
	if err != nil {
		return err
	}

	i.enqueue(msg)

	return nil
}

func (i *transportInstance) Receive() <-chan qbft.Msg[core.Duty, [32]byte] {
	return i.receive
}

// randomNormDuration returns a random duration from a normal distribution with
// the given mean and standard deviation. The duration is always positive.
func randomNormDuration(mean time.Duration, stdDev time.Duration, random *rand.Rand) time.Duration {
	norm := random.NormFloat64()*float64(stdDev) + float64(mean)
	if norm < 0 {
		norm = 0
	}

	return time.Duration(norm)
}

func sinceMSFunc(clock clockwork.Clock) func() int64 {
	var mu sync.RWMutex
	t0 := clock.Now()

	return func() int64 {
		mu.RLock()
		defer mu.RUnlock()

		return clock.Since(t0).Milliseconds()
	}
}
