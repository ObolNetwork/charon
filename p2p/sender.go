// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio/pbio"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	senderHysteresis   = 3
	senderBuffer       = senderHysteresis + 1
	maxMsgSize         = 128 << 20 // 128MB
	defaultRcvTimeout  = time.Second * 5
	defaultSendTimeout = defaultRcvTimeout + 2*time.Second // Allow for up to 1s hop latency (2s RTT)
)

var (
	defaultWriterFunc = func(s network.Stream) pbio.Writer { return pbio.NewDelimitedWriter(s) }
	defaultReaderFunc = func(s network.Stream) pbio.Reader { return pbio.NewDelimitedReader(s, maxMsgSize) }
)

// SendFunc is an abstract function responsible for sending libp2p messages.
type SendFunc func(context.Context, host.Host, protocol.ID, peer.ID, proto.Message, ...SendRecvOption) error

// SendReceiveFunc is an abstract function responsible for sending a libp2p request and returning
// (populating) a libp2p response.
type SendReceiveFunc func(ctx context.Context, p2pNode host.Host, peerID peer.ID,
	req, resp proto.Message, protocol protocol.ID, opts ...SendRecvOption) error

var (
	_ SendFunc = Send
	_ SendFunc = (&Sender{}).SendAsync
)

// errorBuffer holds a slice of errors, and mutexes access to it with a sync.RWMutex.
type errorBuffer struct {
	store []error
	m     sync.RWMutex
}

// add adds err to the buffer.
func (eb *errorBuffer) add(err error) {
	eb.m.Lock()
	defer eb.m.Unlock()

	eb.store = append(eb.store, err)
}

// get gets idx from the buffer.
func (eb *errorBuffer) get(idx int) error {
	eb.m.RLock()
	defer eb.m.RUnlock()

	return eb.store[idx]
}

// len returns the length of the buffer.
func (eb *errorBuffer) len() int {
	eb.m.RLock()
	defer eb.m.RUnlock()

	return len(eb.store)
}

// trim trims the buffer by the given amount.
func (eb *errorBuffer) trim(by int) {
	eb.m.Lock()
	defer eb.m.Unlock()

	eb.store = eb.store[len(eb.store)-by:]
}

type peerState struct {
	failing atomic.Bool
	buffer  errorBuffer
}

// Sender provides an API for sending libp2p messages, both synchronous and asynchronous.
// It also provides log filtering for async sending, mitigating
// error storms when peers are down.
type Sender struct {
	states sync.Map // map[peer.ID]peerState
}

// addResult adds the result of sending a p2p message to the internal state and possibly logs a status change.
func (s *Sender) addResult(ctx context.Context, peerID peer.ID, err error) {
	state := &peerState{}
	if val, ok := s.states.Load(peerID); ok {
		state, ok = val.(*peerState)
		if !ok {
			log.Warn(ctx, "Internal error: Type assertion failed for peer state. This indicates a bug in peer state management and should be reported", err, z.Str("peer", PeerName(peerID)))
			return
		}
	}

	state.buffer.add(err)

	if state.buffer.len() > senderBuffer { // Trim buffer
		state.buffer.trim(senderBuffer)
	}

	failure := err != nil
	success := !failure

	if success && state.failing.Load() {
		// See if we have senderHysteresis successes i.o.t. change state to success.
		full := state.buffer.len() == senderBuffer
		oldestFailure := state.buffer.get(0) != nil
		othersSuccess := true

		for i := 1; i < state.buffer.len(); i++ {
			if state.buffer.get(i) != nil {
				othersSuccess = false
				break
			}
		}

		if full && oldestFailure && othersSuccess {
			state.failing.Store(false)
			log.Info(ctx, "P2P sending recovered", z.Str("peer", PeerName(peerID)))
		}
	} else if failure && (state.buffer.len() == 1 || !state.failing.Load()) {
		// First attempt failed or state changed to failing
		if _, ok := dialErrMsgs(err); !ok { // Only log non-dial errors
			log.Warn(ctx, "P2P message sending failed to peer. Check network connectivity and peer availability", err, z.Str("peer", PeerName(peerID)))
		}

		state.failing.Store(true)
	}

	s.states.Store(peerID, state)
}

// SendAsync returns nil and sends a libp2p message asynchronously.
// It logs results on state change (success to/from failure).
// It implements SendFunc.
func (s *Sender) SendAsync(parent context.Context, p2pNode host.Host, protoID protocol.ID, peerID peer.ID,
	msg proto.Message, opts ...SendRecvOption,
) error {
	//nolint:gosec // The use of background context is intentional.
	go func() {
		// Clone the context since parent context may be closed soon.
		ctx := log.CopyFields(context.Background(), parent)

		err := withRelayRetry(func() error {
			return Send(ctx, p2pNode, protoID, peerID, msg, opts...)
		})
		s.addResult(ctx, peerID, err)
	}()

	return nil
}

// SendReceive sends and receives a libp2p request and response message pair synchronously and then closes the stream.
// The provided response proto will be populated if err is nil.
// It logs results on state change (success to/from failure).
// It implements SendReceiveFunc.
func (s *Sender) SendReceive(ctx context.Context, p2pNode host.Host, peerID peer.ID, req, resp proto.Message,
	protocol protocol.ID, opts ...SendRecvOption,
) error {
	err := withRelayRetry(func() error {
		return SendReceive(ctx, p2pNode, peerID, req, resp, protocol, opts...)
	})
	s.addResult(ctx, peerID, err)

	return err
}

// withRelayRetry wraps a function and retries it once if the error is a relay error.
func withRelayRetry(fn func() error) error {
	err := fn()
	if IsRelayError(err) { // Retry once if relay error
		time.Sleep(time.Millisecond * 100)

		err = fn()
	}

	return err
}

type SendRecvOption func(*sendRecvOpts)

type sendRecvOpts struct {
	protocols         []protocol.ID // Protocols ordered by higher priority first
	writersByProtocol map[protocol.ID]func(network.Stream) pbio.Writer
	readersByProtocol map[protocol.ID]func(network.Stream) pbio.Reader
	rttCallback       func(time.Duration)
	receiveTimeout    time.Duration
	sendTimeout       time.Duration
	retries           int    // Number of additional send attempts after a failure.
	metricTopic       string // Optional sub-protocol label for the send_duration metric.
}

// WithReceiveTimeout returns an option for SendReceive that sets a timeout for handling incoming messages.
func WithReceiveTimeout(timeout time.Duration) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.receiveTimeout = timeout
	}
}

// WithSendTimeout returns an option for SendReceive that sets a timeout for sending messages.
// The timeout is the total wall-clock budget for the call, including all retry attempts
// and backoff when combined with WithRetries.
func WithSendTimeout(timeout time.Duration) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.sendTimeout = timeout
	}
}

// WithRetries returns an option that retries a failed send up to the given number of
// additional attempts, each on a fresh stream, backing off briefly in between. The whole
// sequence shares the send timeout as its total budget, so retries never extend a send
// beyond it; each attempt is capped at its slice of the budget, so a stalled stream
// cannot starve the remaining attempts. Only use it for protocols whose handlers tolerate
// duplicate delivery, since a send that failed on the sender side may still have been
// delivered (e.g. DKG ceremony messages, which are deduplicated by all receivers).
func WithRetries(retries int) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.retries = max(retries, 0)
	}
}

// WithSendMetricTopic returns an option that adds a topic label to the send_duration metric.
// Use a small bounded set of values (e.g. a message-type name) to keep metric cardinality low.
func WithSendMetricTopic(topic string) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.metricTopic = topic
	}
}

// WithSendReceiveRTT returns an option for SendReceive that sets a callback for the RTT.
func WithSendReceiveRTT(callback func(time.Duration)) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.rttCallback = callback
	}
}

// WithDelimitedProtocol returns an option that adds a length delimited read/writer for the provide protocol.
func WithDelimitedProtocol(pID protocol.ID) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.protocols = append([]protocol.ID{pID}, opts.protocols...) // Add to front
		opts.writersByProtocol[pID] = func(s network.Stream) pbio.Writer { return pbio.NewDelimitedWriter(s) }
		opts.readersByProtocol[pID] = func(s network.Stream) pbio.Reader { return pbio.NewDelimitedReader(s, maxMsgSize) }
	}
}

// WithReadLimit returns an option that caps the maximum size in bytes of a single
// message read for the registered protocol(s), overriding the default maxMsgSize (128MB).
// Use a tighter limit for protocols whose legitimate messages are known to be much
// smaller, to bound the receive/decode/allocation cost of oversized (potentially
// malicious) messages before they ever reach the handler.
func WithReadLimit(limit int) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		for _, pID := range opts.protocols {
			opts.readersByProtocol[pID] = func(s network.Stream) pbio.Reader {
				return pbio.NewDelimitedReader(s, limit)
			}
		}
	}
}

// SetFuzzerDefaultsUnsafe sets default reader and writer functions to fuzzed versions of the same if p2p fuzz is enabled.
//
// The fuzzReaderWriter is responsible for creating a customized reader and writer for each network stream
// associated with a specific protocol. The reader and writer implement the pbio.Reader and pbio.Writer interfaces respectively
// respectively, from the "pbio" package.
func SetFuzzerDefaultsUnsafe() {
	defaultWriterFunc = func(s network.Stream) pbio.Writer {
		return fuzzReaderWriter{w: pbio.NewDelimitedWriter(s)}
	}
	defaultReaderFunc = func(network.Stream) pbio.Reader {
		return fuzzReaderWriter{}
	}
}

// defaultSendRecvOpts returns the default sendRecvOpts, it uses the legacy writers and noop rtt callback.
func defaultSendRecvOpts(pID protocol.ID) sendRecvOpts {
	return sendRecvOpts{
		protocols: []protocol.ID{pID},
		writersByProtocol: map[protocol.ID]func(s network.Stream) pbio.Writer{
			pID: defaultWriterFunc,
		},
		readersByProtocol: map[protocol.ID]func(s network.Stream) pbio.Reader{
			pID: defaultReaderFunc,
		},
		rttCallback:    func(time.Duration) {},
		receiveTimeout: defaultRcvTimeout,
		sendTimeout:    defaultSendTimeout,
	}
}

// withRetries calls fn and retries it up to the given number of additional times,
// backing off briefly between attempts. The whole sequence (attempts and backoff)
// is bounded by the deadline, so retries never extend a send beyond its configured
// send timeout. Cancellation stops retrying and surfaces as the context error (with
// the last attempt error attached as a field), so callers can detect it with errors.Is.
func withRetries(ctx context.Context, retries int, deadline time.Time, fn func() error) error {
	var err error

	for attempt := 0; ; attempt++ {
		err = fn()
		if err == nil || attempt >= retries {
			return err
		}

		backoff := expbackoff.Backoff(expbackoff.FastConfig, attempt)
		if !time.Now().Add(backoff).Before(deadline) {
			return err // Budget exhausted, another attempt would fail its deadline immediately.
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Wrap(ctx.Err(), "aborting send retries", z.Err(err))
		case <-timer.C:
		}
	}
}

// SendReceive sends and receives a libp2p request and response message
// pair synchronously and then closes the stream.
// The provided response proto will be populated if err is nil.
// It implements SendReceiveFunc.
func SendReceive(ctx context.Context, p2pNode host.Host, peerID peer.ID,
	req, resp proto.Message, pID protocol.ID, opts ...SendRecvOption,
) error {
	if !isZeroProto(resp) {
		return errors.New("bug: response proto must be zero value")
	}

	o := defaultSendRecvOpts(pID)
	for _, opt := range opts {
		opt(&o)
	}

	// The send timeout is the total budget for the whole call. Unlike a one-way Send, each
	// SendReceive attempt may use the full remaining budget rather than a fixed slice: the
	// response wait is a legitimate long operation (a peer may take up to its receive
	// timeout to reply), so slicing it would abort valid slow responses. Retries therefore
	// only fire on attempts that fail fast enough to leave budget (e.g. dial errors); a
	// stalled attempt consumes the budget and is not retried, since a delivered request to
	// a slow peer must be waited out, not re-sent.
	deadline := time.Now().Add(o.sendTimeout)

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	return withRetries(ctx, o.retries, deadline, func() error {
		// A failed attempt may have partially populated the response.
		proto.Reset(resp)

		return sendReceive(ctx, p2pNode, peerID, req, resp, pID, o, deadline)
	})
}

// attemptDeadline returns the deadline for a single send attempt: its slice of the
// total budget, capped by the overall deadline.
func attemptDeadline(attemptTimeout time.Duration, overall time.Time) time.Time {
	deadline := time.Now().Add(attemptTimeout)
	if deadline.After(overall) {
		return overall
	}

	return deadline
}

// sendReceive is a single SendReceive attempt.
func sendReceive(ctx context.Context, p2pNode host.Host, peerID peer.ID,
	req, resp proto.Message, pID protocol.ID, o sendRecvOpts, deadline time.Time,
) error {
	tStart := time.Now()

	protoLabel := string(pID) // Updated to the negotiated protocol once NewStream succeeds.

	defer func() {
		sendDurations.WithLabelValues(PeerName(peerID), protoLabel, o.metricTopic).Observe(time.Since(tStart).Seconds())
	}()

	// Circuit relay connections are transient
	s, err := p2pNode.NewStream(network.WithAllowLimitedConn(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "new stream", z.Any("protocols", o.protocols), z.Str("peer", PeerName(peerID)))
	}
	defer s.Close()

	protoLabel = string(s.Protocol())

	if err := s.SetDeadline(deadline); err != nil {
		return errors.Wrap(err, "set deadline", z.Str("peer", PeerName(peerID)))
	}

	writeFunc, ok := o.writersByProtocol[s.Protocol()]
	if !ok {
		return errors.New("no writer for protocol", z.Any("protocol", s.Protocol()))
	}

	readFunc, ok := o.readersByProtocol[s.Protocol()]
	if !ok {
		return errors.New("no reader for protocol", z.Any("protocol", s.Protocol()))
	}

	writer := writeFunc(s)
	reader := readFunc(s)

	t0 := time.Now()

	if err = writer.WriteMsg(req); err != nil {
		return errors.Wrap(err, "write request", z.Any("protocol", s.Protocol()), z.Str("peer", PeerName(peerID)))
	}

	if err := s.CloseWrite(); err != nil {
		// A canceled-stream error here is benign: the request was already written and
		// delivered above, and the peer resetting our send-direction (STOP_SENDING) does
		// not affect the receive-direction, so the response is still readable below.
		// This happens much more frequently when QUIC is enabled.
		//
		//nolint:revive // Prioritise readability.
		if isCanceledStreamErr(err) {
			log.Debug(ctx, "Closing write of canceled stream", z.Err(err), z.Any("protocol", s.Protocol()))
		} else {
			return errors.Wrap(err, "close write", z.Any("protocol", s.Protocol()), z.Str("peer", PeerName(peerID)))
		}
	}

	if err = reader.ReadMsg(resp); err != nil {
		return errors.Wrap(err, "read response", z.Any("protocol", s.Protocol()), z.Str("peer", PeerName(peerID)))
	}

	o.rttCallback(time.Since(t0))

	return nil
}

// Send sends a libp2p message synchronously. It implements SendFunc.
func Send(ctx context.Context, p2pNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message,
	opts ...SendRecvOption,
) error {
	o := defaultSendRecvOpts(protoID)
	for _, opt := range opts {
		opt(&o)
	}

	// The send timeout is the total budget for the call: stream creation and all
	// attempts share one deadline, also enforced via the context so dialing and
	// protocol negotiation cannot block past it. Each attempt gets a slice of the
	// budget, so a stalled stream cannot consume it all and a retry on a fresh
	// stream can still occur.
	deadline := time.Now().Add(o.sendTimeout)
	attemptTimeout := o.sendTimeout / time.Duration(o.retries+1)

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	return withRetries(ctx, o.retries, deadline, func() error {
		// Bound the attempt's dialing and negotiation by its deadline as well,
		// so a hung dial cannot consume the remaining attempts' budget.
		attemptDL := attemptDeadline(attemptTimeout, deadline)

		attemptCtx, cancel := context.WithDeadline(ctx, attemptDL)
		defer cancel()

		return send(attemptCtx, p2pNode, protoID, peerID, msg, o, attemptDL)
	})
}

// send is a single Send attempt.
func send(ctx context.Context, p2pNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message,
	o sendRecvOpts, deadline time.Time,
) error {
	t0 := time.Now()

	protoLabel := string(protoID)
	if len(o.protocols) > 0 {
		protoLabel = string(o.protocols[0])
	}

	defer func() {
		sendDurations.WithLabelValues(PeerName(peerID), protoLabel, o.metricTopic).Observe(time.Since(t0).Seconds())
	}()
	// Circuit relay connections are transient
	s, err := p2pNode.NewStream(network.WithAllowLimitedConn(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "p2pNode stream", z.Str("peer", PeerName(peerID)))
	}
	defer s.Close()

	protoLabel = string(s.Protocol())

	if err := s.SetDeadline(deadline); err != nil {
		return errors.Wrap(err, "set deadline", z.Str("peer", PeerName(peerID)))
	}

	writeFunc, ok := o.writersByProtocol[s.Protocol()]
	if !ok {
		return errors.New("no writer for protocol", z.Any("protocol", s.Protocol()))
	}

	if err = writeFunc(s).WriteMsg(msg); err != nil {
		return errors.Wrap(err, "write message", z.Any("protocol", s.Protocol()), z.Str("peer", PeerName(peerID)))
	}

	return nil
}

// isCanceledStreamErr returns true if the error is the benign QUIC stream error
// returned when closing a stream whose send-direction the peer has already reset
// (via STOP_SENDING). It occurs much more frequently when QUIC is enabled.
func isCanceledStreamErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "close called for canceled stream")
}

// protocolPrefix returns the common prefix of the provided protocol IDs,
// suffixed with "*" if they are not all identical.
//
// Only pass IDs that share a non-empty common prefix. The result is the name
// RegisterHandler registers with the stream muxer, which libp2p identify then
// advertises to peers, so IDs that diverge at the first byte collapse to a bare
// "*" and peers are told we support that instead of any real protocol.
func protocolPrefix(pIDs ...protocol.ID) protocol.ID {
	if len(pIDs) == 0 {
		return ""
	}

	if len(pIDs) == 1 {
		return pIDs[0]
	}

	prefix := pIDs[0]
	for _, pID := range pIDs {
		for i := 0; i < len(prefix) && i < len(pID); i++ {
			if prefix[i] != pID[i] {
				prefix = prefix[:i]
				break
			}
		}
	}

	if len(prefix) < len(pIDs[0]) {
		prefix += "*"
	}

	return prefix
}

// isZeroProto returns true if the provided proto message is zero.
//
// Note this function is inefficient for the negative case (i.e. when the message is not zero)
// as it copies the input argument.
func isZeroProto(m proto.Message) bool {
	if m == nil {
		return false
	}

	clone := proto.Clone(m)
	proto.Reset(clone)

	return proto.Equal(m, clone)
}
