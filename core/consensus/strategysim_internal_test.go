// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
)

const (
	ms005  = time.Millisecond * 5
	ms010  = time.Millisecond * 10
	ms025  = time.Millisecond * 25
	ms050  = time.Millisecond * 50
	ms100  = time.Millisecond * 100
	ms250  = time.Millisecond * 250
	ms500  = time.Millisecond * 500
	ms750  = time.Millisecond * 750
	ms1000 = time.Millisecond * 1000
	ms1500 = time.Millisecond * 1500
	ms2500 = time.Millisecond * 2500
	ms5000 = time.Millisecond * 5000
	min1   = time.Minute * 1
)

type roundTimerFunc func(clock clockwork.Clock) roundTimer

var (
	incTimer = func(clock clockwork.Clock) roundTimer {
		timer := newIncreasingRoundTimer()
		timer.clock = clock

		return timer
	}
	doubleTimer = func(clock clockwork.Clock) roundTimer {
		timer := newDoubleLeadRoundTimer()
		timer.clock = clock

		return timer
	}

	inc2Timer = func(clock clockwork.Clock) roundTimer {
		return incRoundTimer2{clock: clock}
	}

	expTimer = func(clock clockwork.Clock) roundTimer {
		return expRoundTimer{clock: clock}
	}
)

func TestSimulatorOnce(t *testing.T) {
	syncer, _, _ := zap.Open("stderr")
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
	}, true, syncer)

	require.Equal(t, 4, len(results))
	require.False(t, isUndecided(results))
}

func TestMatrix(t *testing.T) {
	t.Skip("Skip matrix test") // Uncomment this to run the test.

	timers := []Named[roundTimerFunc]{
		{"inc", incTimer},
		{"double", doubleTimer},
		{"inc2", inc2Timer},
		{"exp", expTimer},
	}

	testRoundTimers(t, timers)
}

type matrixResult struct {
	Undecided   int
	Total       int
	RoundSum    int
	DurationSum time.Duration
}

func (r matrixResult) AvgRound() float64 {
	return float64(r.RoundSum) / float64(r.Total)
}

func (r matrixResult) AvgDuration() time.Duration {
	return r.DurationSum / time.Duration(r.Total)
}

func testRoundTimers(t *testing.T, timers []Named[roundTimerFunc]) {
	t.Helper()
	const itersPerConfig = 100 // Tune this for test duration vs accuracy

	sizes := []NamedTuple[int, int]{
		{"small-all", 4, 4},  // Up: 4 of 4
		{"small-min", 3, 4},  // Up: 3 of 4
		{"medium-all", 6, 6}, // Up: 6 of 6
		{"medium-min", 4, 6}, // Up: 4 of 6
		{"large-all", 9, 9},  // Up: 9 of 9
		{"large-min", 6, 9},  // Up: 6 of 9
	}

	distributions := []NamedTuple[[]time.Duration, []time.Duration]{
		{
			Name:   "colocated",
			Value1: []time.Duration{ms005, ms010},               // latencies
			Value2: []time.Duration{ms005, ms010, ms025, ms050}, // latencies
		},
		{
			Name:   "regional",
			Value1: []time.Duration{ms010, ms025},        // latencies
			Value2: []time.Duration{ms050, ms100, ms250}, // latencies
		},
		{
			Name:   "global",
			Value1: []time.Duration{ms050, ms100},                      // latencies
			Value2: []time.Duration{ms250, ms250, ms500, ms500, ms750}, // latencies
		},
	}

	var allConfigs []ssConfig
	for _, size := range sizes {
		names := []string{size.Name, "", ""}
		for _, dist := range distributions {
			names[1] = dist.Name
			for _, timer := range timers {
				names[2] = timer.Name
				configs := randomConfigs(names, size.Value2, itersPerConfig, timer.Value1, dist.Value1, dist.Value2)
				configs = disableRandomNodes(configs, size.Value1)
				allConfigs = append(allConfigs, configs...)
			}
		}
	}

	fjResults, cancel := forkjoin.NewWithInputs(
		context.Background(),
		func(_ context.Context, config ssConfig) (Named[[]result], error) {
			name := strings.Join(config.names, " ")
			buf := zaptest.Buffer{}
			results := testStrategySimulator(t, config, true, &buf)
			// Uncomment this to see undecided config and logs
			// if isUndecided(results) {
			// 	fmt.Printf("undedicded config=%#v\n", config)
			// 	fmt.Println(buf.String())
			// }
			return Named[[]result]{name, results}, nil
		},
		allConfigs,
		forkjoin.WithWorkers(itersPerConfig),
	)
	defer cancel()

	results, err := fjResults.Flatten()
	require.NoError(t, err)

	printFunc, flush := newPrintFunc()

	for _, size := range sizes {
		names := []string{size.Name, "", ""}
		for _, dist := range distributions {
			names[1] = dist.Name
			printFunc(nil, matrixResult{}) // Empty line
			for _, timer := range timers {
				names[2] = timer.Name
				printResults(printFunc, results, names)
			}
		}
	}

	flush()
}

func newPrintFunc() (func(names []string, result matrixResult), func()) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	_, _ = fmt.Fprintln(writer, "Size\tDistribution\tTimer\tTotal\tUndecided\tAvgRound\tAvgDuration")

	return func(names []string, result matrixResult) {
			if len(names) == 0 {
				_, _ = fmt.Fprintln(writer, "", "\t", "", "\t", "", "\t", "", "\t", "", "\t", "", "\t", "")
				return
			}

			_, _ = fmt.Fprintln(writer,
				names[0], "\t",
				names[1], "\t",
				names[2], "\t",
				result.Total, "\t",
				result.Undecided, "\t",
				result.AvgRound(), "\t",
				result.AvgDuration())
		}, func() {
			_ = writer.Flush()
		}
}

func printResults(printFunc func([]string, matrixResult), results []Named[[]result], names []string) {
	name := strings.Join(names, " ")

	var res matrixResult
	for _, result := range results {
		if result.Name != name {
			continue
		}

		res.Total++
		if isUndecided(result.Value1) {
			res.Undecided++
			continue
		}

		res.DurationSum += quorumDecidedDuration(result.Value1)
		res.RoundSum += decidedRound(result.Value1)
	}

	printFunc(names, res)
}

// peerID is a peer identifier of which the zero value is invalid.
type peerID struct {
	Idx int64
	OK  bool
}

type ssConfig struct {
	names          []string
	seed           int
	latencyStdDev  time.Duration
	latencyPerPeer map[int64]time.Duration
	startByPeer    map[int64]time.Duration
	roundTimerFunc func(clockwork.Clock) roundTimer
	timeout        time.Duration
}

func testStrategySimulator(t *testing.T, conf ssConfig, verbose bool, syncer zapcore.WriteSyncer) []result {
	t.Helper()
	random := rand.New(rand.NewSource(int64(conf.seed)))
	clock := clockwork.NewFakeClockAt(time.Now().Truncate(time.Hour))

	if verbose {
		log.InitConsoleForT(t, syncer, log.WithClock(clock))
	}

	t0 := clock.Now()
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
			verbose,
			conf.roundTimerFunc(clock),
			func(qcommit []qbft.Msg[core.Duty, [32]byte]) {
				res = result{
					PeerIdx:  p.Idx,
					Decided:  true,
					Round:    qcommit[0].Round(),
					Duration: clock.Since(t0),
				}
			},
		)

		// Unique non-zero value per peer
		var val [32]byte
		val[0], val[1] = byte(0xFF), byte(p.Idx)

		// Delay start of peer
		select {
		case <-ctx.Done():
			return res, nil
		case <-clock.After(conf.startByPeer[p.Idx]):
		}

		topic := fmt.Sprintf("peer%d", p.Idx)
		topic = fmt.Sprintf("\x1b[%dm%s\x1b[0m", uint8(30+p.Idx), topic)
		ctx = log.WithTopic(ctx, topic)
		if verbose {
			log.Debug(ctx, "Starting peer", z.Any("delayed", conf.startByPeer[p.Idx]))
		}
		err := qbft.Run(ctx, def, transports[p.Idx], core.Duty{Slot: int64(conf.seed)}, p.Idx, val)
		if err != nil && !errors.Is(err, context.Canceled) {
			return res, err
		}

		return res, nil
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
	if err != nil && !errors.Is(err, context.Canceled) {
		require.Fail(t, "unexpected error", err)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].PeerIdx < results[j].PeerIdx
	})

	return results
}

func newSimDefinition(nodes int, verbose bool, roundTimer roundTimer,
	decideCallback func(qcommit []qbft.Msg[core.Duty, [32]byte]),
) qbft.Definition[core.Duty, [32]byte] {
	quorum := qbft.Definition[int, int]{Nodes: nodes}.Quorum()
	return qbft.Definition[core.Duty, [32]byte]{
		IsLeader: func(duty core.Duty, round, process int64) bool {
			return leader(duty, round, nodes) == process
		},
		Decide: func(ctx context.Context, duty core.Duty, _ [32]byte, qcommit []qbft.Msg[core.Duty, [32]byte]) {
			decideCallback(qcommit)
		},
		NewTimer:  roundTimer.Timer,
		LogUnjust: func(context.Context, core.Duty, int64, qbft.Msg[core.Duty, [32]byte]) {},
		LogRoundChange: func(ctx context.Context, duty core.Duty, process,
			round, newRound int64, uponRule qbft.UponRule, msgs []qbft.Msg[core.Duty, [32]byte],
		) {
			if !verbose {
				return
			}
			fields := []z.Field{
				z.Any("rule", uponRule),
				z.I64("round", round),
				z.I64("new_round", newRound),
			}

			steps := groupRoundMessages(msgs, nodes, round, int(leader(duty, round, nodes)))
			for _, step := range steps {
				fields = append(fields, z.Str(step.Type.String(), fmtStepPeers(step)))
			}
			if uponRule == qbft.UponRoundTimeout {
				fields = append(fields, z.Str("timeout_reason", timeoutReason(steps, round, quorum)))
			}
			log.Debug(ctx, "QBFT round changed", fields...)
		},
		// LogUponRule logs upon rules at debug level.
		LogUponRule: func(ctx context.Context, _ core.Duty, _, round int64,
			_ qbft.Msg[core.Duty, [32]byte], uponRule qbft.UponRule,
		) {
			if !verbose {
				return
			}
			log.Debug(ctx, "QBFT upon rule triggered", z.Any("rule", uponRule), z.I64("round", round))
		},
		// Nodes is the number of nodes.
		Nodes: nodes,

		// FIFOLimit caps the max buffered messages per peer.
		FIFOLimit: recvBuffer,
	}
}

type result struct {
	PeerIdx  int64
	Decided  bool
	Round    int64
	Duration time.Duration
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
		values[impl.Value()] = dummy
		values[impl.PreparedValue()] = dummy
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

func pick[T any](slice []T, i int) T {
	return slice[i%len(slice)]
}

func decidedRound(results []result) int {
	for _, res := range results {
		if res.Decided {
			return int(res.Round)
		}
	}

	panic("no decided round")
}

func isUndecided(results []result) bool {
	q := cluster.Threshold(len(results))
	var decided int
	for _, res := range results {
		if res.Decided {
			decided++
		}
	}

	return decided < q
}

func quorumDecidedDuration(results []result) time.Duration {
	q := cluster.Threshold(len(results))
	var durations []time.Duration
	for _, res := range results {
		if !res.Decided {
			continue
		}
		durations = append(durations, res.Duration)
	}

	if len(durations) < q {
		panic("not enough durations")
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	return durations[q-1]
}

func TestExp(t *testing.T) {
	timer := incRoundTimer2{clock: clockwork.NewRealClock()}
	for i := 1; i < 5; i++ {
		timer.Timer(int64(i))
	}
}

type incRoundTimer2 struct {
	clock clockwork.Clock
}

func (t incRoundTimer2) Timer(round int64) (<-chan time.Time, func()) {
	duration := incRoundStart
	for i := 1; i < int(round); i++ {
		duration += incRoundStart
	}

	timer := t.clock.NewTimer(duration)

	return timer.Chan(), func() {}
}

type expRoundTimer struct {
	clock clockwork.Clock
}

func (t expRoundTimer) Timer(round int64) (<-chan time.Time, func()) {
	duration := incRoundStart
	for i := 1; i < int(round); i++ {
		duration *= 2
	}

	timer := t.clock.NewTimer(duration)

	return timer.Chan(), func() {}
}

func randomConfigs(names []string, peers int, n int, timer func(clockwork.Clock) roundTimer,
	stdDev []time.Duration, latencies []time.Duration,
) []ssConfig {
	random := rand.New(rand.NewSource(0))

	peerLatencies := randomPeerLatencies(peers, n, latencies, random)

	var res []ssConfig
	for i := 0; i < n; i++ {
		res = append(res, ssConfig{
			names:          append([]string(nil), names...),
			seed:           i,
			latencyStdDev:  pick(stdDev, i),
			latencyPerPeer: peerLatencies[i],
			startByPeer:    normalStartLatencies(peers, random),
			roundTimerFunc: timer,
			timeout:        min1,
		})
	}

	return res
}

func randomPeerLatencies(peers int, n int, selectFrom []time.Duration, random *rand.Rand) []map[int64]time.Duration {
	var resp []map[int64]time.Duration
	for i := 0; i < n; i++ {
		m := make(map[int64]time.Duration)
		for i := 0; i < peers; i++ {
			m[int64(i)] = selectFrom[random.Intn(len(selectFrom))]
		}
		resp = append(resp, m)
	}

	return resp
}

// proposalLatencyPercentiles is a map of percentiles to expected BN beacon_node_proposal
// endpoint latencies (in seconds) as measures by our central monitoring.
var (
	proposalLatencyPercentiles = map[float64]float64{
		0.1:  0.2,
		0.25: 0.296,
		0.5:  0.429,
		0.75: 0.664,
		0.9:  0.877,
		0.99: 1.5,
	}
	// proposalMean and proposalStdDev are the mean and standard deviation of the above percentiles.
	proposalMean, proposalStdDev = estimateMeanStdDev(proposalLatencyPercentiles)
)

// normalStartLatencies returns a map of peer indices to normal distribution random latencies based on real-world
// proposalLatencyPercentiles.
func normalStartLatencies(peers int, random *rand.Rand) map[int64]time.Duration {
	resp := make(map[int64]time.Duration, peers)
	for i := 0; i < peers; i++ {
		resp[int64(i)] = normalDuration(proposalMean, proposalStdDev, random)
	}

	return resp
}

func normalDuration(mean, stdDev float64, random *rand.Rand) time.Duration {
	randomValue := random.NormFloat64()*stdDev + mean
	if randomValue < 0 {
		return 0
	}

	return time.Duration(randomValue * float64(time.Second))
}

func estimateMeanStdDev(percentiles map[float64]float64) (float64, float64) {
	// This function estimates the mean and standard deviation based on the provided percentiles.
	// You can use more sophisticated methods or more percentiles to get a better estimation.
	mean := (percentiles[0.25] + percentiles[0.5] + percentiles[0.75]) / 3
	stdDev := (percentiles[0.75] - percentiles[0.25]) / 1.35 // Assumes Q3-Q1 range contains about 68% of the data

	return mean, stdDev
}

func disableRandomNodes(configs []ssConfig, n int) []ssConfig {
	random := rand.New(rand.NewSource(0))
	for _, config := range configs {
		config.startByPeer[int64(random.Intn(n))] = time.Hour
	}

	return configs
}

type Named[T any] struct {
	Name   string
	Value1 T
}
type NamedTuple[T1, T2 any] struct {
	Name   string
	Value1 T1
	Value2 T2
}
