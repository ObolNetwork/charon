// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:forbidigo // This is a test that prints to stdout.
package consensus

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
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
	ms005      = time.Millisecond * 5
	ms010      = time.Millisecond * 10
	ms025      = time.Millisecond * 25
	ms050      = time.Millisecond * 50
	ms100      = time.Millisecond * 100
	ms250      = time.Millisecond * 250
	ms500      = time.Millisecond * 500
	ms750      = time.Millisecond * 750
	ms1000     = time.Millisecond * 1000
	ms1500     = time.Millisecond * 1500
	ms2500     = time.Millisecond * 2500
	ms5000     = time.Millisecond * 5000
	simTimeout = time.Second * 12

	disabled = time.Hour * 999
)

type roundTimerFunc func(clock clockwork.Clock) roundTimer

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
		roundTimerFunc: newInc,
		timeout:        simTimeout,
	}, syncer)

	require.Equal(t, 4, len(results))
	require.False(t, isUndecided(results))
}

func TestMatrix(t *testing.T) {
	t.Skip("Skip matrix test") // Comment this to run the test.

	const itersPerConfig = 500 // Tune this for test duration vs accuracy

	testRoundTimers(t,
		[]roundTimerFunc{
			newInc,

			newExp(time.Millisecond * 1000),

			newExpDouble(time.Millisecond * 1000),

			newLinear(time.Millisecond * 1000),
			newLinearDouble(time.Millisecond * 1000),
		},
		itersPerConfig)
}

type matrixResult struct {
	Undecided int
	Total     int
	Rounds    []int
	Durations []time.Duration
}

func (r matrixResult) UndecidedPercent() float64 {
	return 100 * float64(r.Undecided) / float64(r.Total)
}

func (r matrixResult) AvgRound() float64 {
	if len(r.Rounds) == 0 {
		return 0
	}
	var total float64
	for _, r := range r.Rounds {
		total += float64(r)
	}

	return total / float64(len(r.Rounds))
}

func (r matrixResult) AvgDuration() time.Duration {
	if len(r.Durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range r.Durations {
		total += d
	}

	return total / time.Duration(len(r.Durations))
}

func (r matrixResult) StdDevDuration() time.Duration {
	if len(r.Durations) == 0 {
		return 0
	}

	return time.Duration(stddev(r.Durations, func(d time.Duration) float64 {
		return float64(d)
	}))
}

func testRoundTimers(t *testing.T, timers []roundTimerFunc, itersPerConfig int) {
	t.Helper()

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
				names[2] = timerName(timer)
				configs := randomConfigs(names, size.Value2, itersPerConfig, timer, dist.Value1, dist.Value2)
				configs = disableRandomNodes(configs, size.Value2-size.Value1)
				allConfigs = append(allConfigs, configs...)
			}
		}
	}

	for i := 0; i < len(allConfigs); i++ {
		allConfigs[i].index = i
	}

	fjResults, cancel := forkjoin.NewWithInputs(
		context.Background(),
		func(_ context.Context, config ssConfig) (Named[[]result], error) {
			name := strings.Join(config.names, " ")
			var buf zaptest.Buffer
			results := testStrategySimulator(t, config, &buf)
			// Uncomment this to see undecided config and logs
			// if isUndecided(results) {
			//	fmt.Printf("undedicded config=%#v\n", config)
			//	fmt.Printf("results=%#v\n", results)
			//	fmt.Println(buf.String())
			//}
			return Named[[]result]{name, results}, nil
		},
		allConfigs,
		forkjoin.WithInputBuffer(len(allConfigs)),
		forkjoin.WithWorkers(256),
	)
	defer cancel()

	var results []Named[[]result]
	for res := range fjResults {
		require.NoError(t, res.Err)
		results = append(results, res.Output)
		if len(results)%100 == 0 {
			fmt.Printf("Completed %d/%d\n", len(results), len(allConfigs))
		}
	}

	printFunc, flush := newPrintFunc()
	for _, size := range sizes {
		names := []string{size.Name, "", ""}
		for _, dist := range distributions {
			names[1] = dist.Name
			printFunc(nil, matrixResult{}) // Empty line
			for _, timer := range timers {
				names[2] = timerName(timer)
				printResults(printFunc, results, names)
			}
		}
	}
	flush()

	fmt.Printf("\n\nTimer aggregate results\n\n")

	printFunc, flush = newPrintFunc()
	for _, timer := range timers {
		names := []string{"", "", timerName(timer)}
		printAggResults(printFunc, results, names)
	}
	flush()
}

func timerName(timerFunc roundTimerFunc) string {
	return string(timerFunc(nil).Type())
}

func newPrintFunc() (func(names []string, result matrixResult), func()) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	_, _ = fmt.Fprintln(writer, "Size\tDistribution\tTimer\tTotal\tUndecided\tAvgRound\tMeanDuration\tStdDevDuration")

	return func(names []string, result matrixResult) {
			if len(names) == 0 {
				// _, _ = fmt.Fprintln(writer, "", "\t", "", "\t", "", "\t", "", "\t", "", "\t", "", "\t", "")
				return
			}

			_, _ = fmt.Fprintln(writer,
				names[0], "\t",
				names[1], "\t",
				names[2], "\t",
				result.Total, "\t",
				fmt.Sprintf("%.2f%%", result.UndecidedPercent()), "\t",
				fmt.Sprintf("%.2f", result.AvgRound()), "\t",
				fmt.Sprintf("%.2fs", result.AvgDuration().Seconds()), "\t",
				fmt.Sprintf("%.2fs", result.StdDevDuration().Seconds()))
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

		res.Durations = append(res.Durations, quorumDecidedDuration(result.Value1))
		res.Rounds = append(res.Rounds, decidedRound(result.Value1))
	}

	printFunc(names, res)
}

func printAggResults(printFunc func([]string, matrixResult), results []Named[[]result], names []string) {
	name := strings.TrimSpace(strings.Join(names, " "))

	var res matrixResult
	for _, result := range results {
		if !strings.Contains(result.Name, name) {
			continue
		}

		res.Total++
		if isUndecided(result.Value1) {
			res.Undecided++
			continue
		}

		res.Durations = append(res.Durations, quorumDecidedDuration(result.Value1))
		res.Rounds = append(res.Rounds, decidedRound(result.Value1))
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
	index          int
	seed           int
	latencyStdDev  time.Duration
	latencyPerPeer map[int64]time.Duration
	startByPeer    map[int64]time.Duration
	roundTimerFunc func(clockwork.Clock) roundTimer
	timeout        time.Duration
}

func testStrategySimulator(t *testing.T, conf ssConfig, syncer zapcore.WriteSyncer) []result {
	t.Helper()
	random := rand.New(rand.NewSource(int64(conf.seed)))
	clock := clockwork.NewFakeClockAt(time.Now().Truncate(time.Hour))

	logger := log.NewConsoleForT(t, syncer, log.WithClock(clock))
	ctx := log.WithLogger(context.Background(), logger)

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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := cancelAfter(cancel, len(peerIDs))

	work := func(ctx context.Context, p peerID) (result, error) {
		res := result{PeerIdx: p.Idx, Decided: false}
		def := newSimDefinition(
			len(conf.latencyPerPeer),
			conf.roundTimerFunc(clock),
			func(qcommit []qbft.Msg[core.Duty, [32]byte]) {
				res = result{
					PeerIdx:  p.Idx,
					Decided:  true,
					Round:    qcommit[0].Round(),
					Duration: clock.Since(t0),
				}
				done()
			},
		)

		// Setup unique non-zero value per peer
		valCh := make(chan [32]byte, 1)
		enqueueValue := func() {
			var val [32]byte
			val[0], val[1] = byte(0xFF), byte(p.Idx)
			valCh <- val
		}

		topic := fmt.Sprintf("peer%d", p.Idx)
		topic = fmt.Sprintf("\x1b[%dm%s\x1b[0m", uint8(31+p.Idx), topic)
		ctx = log.WithTopic(ctx, topic)

		delay := conf.startByPeer[p.Idx]
		if delay == disabled { // If peer disabled, return immediately
			log.Debug(ctx, "Peer disabled")
			return res, nil
		} else if conf.roundTimerFunc(nil).Type().Eager() { // If timer is eager, delay value asynchronously
			go after(ctx, clock, delay, enqueueValue)
			log.Debug(ctx, "Delaying peer value", z.Any("value_delayed", delay))
		} else {
			log.Debug(ctx, "Delaying peer start", z.Any("start_delayed", delay))
			// If timer isn't eager, delay run synchronously
			if !after(ctx, clock, delay, enqueueValue) {
				return res, nil
			}
		}

		log.Debug(ctx, "Starting peer")

		err := qbft.Run(ctx, def, transports[p.Idx], core.Duty{Slot: int64(conf.seed)}, p.Idx, valCh)
		if err != nil && !errors.Is(err, context.Canceled) {
			return res, err
		}

		return res, nil
	}

	fjResults, fjCancel := forkjoin.NewWithInputs(ctx, work, peerIDs)
	defer fjCancel()

	// Run the simulator until timeout.
	go func() {
		t0 := clock.Now()

		for ctx.Err() == nil {
			gosched()
			clock.Advance(time.Millisecond * 10)
			gosched()
			txSimulator.processBuffer()
			if clock.Since(t0) < conf.timeout {
				continue
			}

			cancel() // Cancel the context to stop consensus.
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

// cancelAfter cancels the provide context after n call to the returned context.
// It is thread safe.
func cancelAfter(cancel context.CancelFunc, n int) context.CancelFunc {
	var mu sync.Mutex
	return func() {
		mu.Lock()
		defer mu.Unlock()
		n--
		if n == 0 {
			cancel()
		}
	}
}

func gosched() {
	for i := 0; i < 3; i++ {
		time.Sleep(time.Microsecond)
		runtime.Gosched()
	}
}

func newSimDefinition(nodes int, roundTimer roundTimer,
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

// after calls callback after duration, unless ctx is cancelled first.
func after(ctx context.Context, clock clockwork.Clock, duration time.Duration, callback func()) bool {
	select {
	case <-ctx.Done():
		return false
	case <-clock.After(duration):
		callback()
		return true
	}
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

func (t incRoundTimer2) Type() timerType {
	return "inc2"
}

func (t incRoundTimer2) Timer(round int64) (<-chan time.Time, func()) {
	duration := incRoundStart
	for i := 1; i < int(round); i++ {
		duration += incRoundStart
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
			timeout:        simTimeout,
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
		size := len(config.latencyPerPeer)
		for i := 0; i < n; i++ {
			config.startByPeer[int64(random.Intn(size))] = disabled
		}
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

type testTimer struct {
	clock        clockwork.Clock
	durationFunc func(round int64) time.Duration
	reset        bool
	double       bool
	eager        bool
	name         string

	mu        sync.Mutex
	timers    map[int64]<-chan time.Time
	deadlines map[int64]time.Time
}

func (t *testTimer) Timer(round int64) (<-chan time.Time, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	duration := t.durationFunc(round)

	if t.double {
		// Fetch previously created deadline.
		if deadline, ok := t.deadlines[round]; ok {
			newDeadline := deadline.Add(duration)
			diff := newDeadline.Sub(t.clock.Now())
			timer := t.clock.NewTimer(diff)

			return timer.Chan(), func() {}
		}
	}
	if !t.reset {
		// Fetch previously created timer.
		if timer, ok := t.timers[round]; ok {
			return timer, func() {}
		}
	} // Else create a new timer.

	deadline := t.clock.Now().Add(duration)
	if t.deadlines == nil {
		t.deadlines = make(map[int64]time.Time)
	}
	t.deadlines[round] = deadline

	timer := t.clock.NewTimer(duration)
	if t.timers == nil {
		t.timers = make(map[int64]<-chan time.Time)
	}
	t.timers[round] = timer.Chan()

	return timer.Chan(), func() {}
}

func (t *testTimer) Type() timerType {
	name := t.name
	if t.eager {
		name += "_eager"
	}

	return timerType(name)
}

func newLinear(d time.Duration) roundTimerFunc {
	return func(clock clockwork.Clock) roundTimer {
		return &testTimer{
			clock: clock,
			durationFunc: func(round int64) time.Duration {
				return d * time.Duration(round)
			},
			reset: false,
			eager: true,
			name:  fmt.Sprintf("linear_%d", d.Milliseconds()),
		}
	}
}

func newExpDouble(d time.Duration) roundTimerFunc {
	return func(clock clockwork.Clock) roundTimer {
		return &testTimer{
			clock: clock,
			durationFunc: func(round int64) time.Duration {
				return d * time.Duration(math.Pow(2, float64(round-1)))
			},
			reset:  false,
			double: true,
			eager:  true,
			name:   fmt.Sprintf("edouble_%d", d.Milliseconds()),
		}
	}
}

func newLinearDouble(d time.Duration) roundTimerFunc {
	return func(clock clockwork.Clock) roundTimer {
		return &testTimer{
			clock: clock,
			durationFunc: func(round int64) time.Duration {
				return d * time.Duration(round)
			},
			reset:  false,
			double: true,
			eager:  true,
			name:   fmt.Sprintf("ldouble_%d", d.Milliseconds()),
		}
	}
}

func newInc(clock clockwork.Clock) roundTimer {
	return &increasingRoundTimer{clock: clock}
}

func newExp(d time.Duration) roundTimerFunc {
	return func(clock clockwork.Clock) roundTimer {
		return &testTimer{
			clock: clock,
			durationFunc: func(round int64) time.Duration {
				return d * time.Duration(math.Pow(2, float64(round-1)))
			},
			reset: false,
			eager: true,
			name:  fmt.Sprintf("exp_%d", d.Milliseconds()),
		}
	}
}

func stddev[T comparable](values []T, toFloat func(T) float64) float64 {
	var sum float64
	for _, v := range values {
		sum += toFloat(v)
	}

	mean := sum / float64(len(values))

	var squaredSum float64
	for _, value := range values {
		difference := toFloat(value) - mean
		squaredSum += difference * difference
	}

	return math.Sqrt(squaredSum / float64(len(values)-1))
}
