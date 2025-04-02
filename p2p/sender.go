// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
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
type SendReceiveFunc func(ctx context.Context, tcpNode host.Host, peerID peer.ID,
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
			log.Warn(ctx, "Type assertion peer state failing", err, z.Str("peer", PeerName(peerID)))
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
			log.Warn(ctx, "P2P sending failing", err, z.Str("peer", PeerName(peerID)))
		}

		state.failing.Store(true)
	}

	s.states.Store(peerID, state)
}

// SendAsync returns nil and sends a libp2p message asynchronously.
// It logs results on state change (success to/from failure).
// It implements SendFunc.
func (s *Sender) SendAsync(parent context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID,
	msg proto.Message, opts ...SendRecvOption,
) error {
	go func() {
		// Clone the context since parent context may be closed soon.
		ctx := log.CopyFields(context.Background(), parent)

		err := withRelayRetry(func() error {
			return Send(ctx, tcpNode, protoID, peerID, msg, opts...)
		})
		s.addResult(ctx, peerID, err)
	}()

	return nil
}

// SendReceive sends and receives a libp2p request and response message pair synchronously and then closes the stream.
// The provided response proto will be populated if err is nil.
// It logs results on state change (success to/from failure).
// It implements SendReceiveFunc.
func (s *Sender) SendReceive(ctx context.Context, tcpNode host.Host, peerID peer.ID, req, resp proto.Message,
	protocol protocol.ID, opts ...SendRecvOption,
) error {
	err := withRelayRetry(func() error {
		return SendReceive(ctx, tcpNode, peerID, req, resp, protocol, opts...)
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
}

// WithReceiveTimeout returns an option for SendReceive that sets a timeout for handling incoming messages.
func WithReceiveTimeout(timeout time.Duration) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.receiveTimeout = timeout
	}
}

// WithSendTimeout returns an option for SendReceive that sets a timeout for sending messages.
func WithSendTimeout(timeout time.Duration) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.sendTimeout = timeout
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

// SendReceive sends and receives a libp2p request and response message
// pair synchronously and then closes the stream.
// The provided response proto will be populated if err is nil.
// It implements SendReceiveFunc.
func SendReceive(ctx context.Context, tcpNode host.Host, peerID peer.ID,
	req, resp proto.Message, pID protocol.ID, opts ...SendRecvOption,
) error {
	if !isZeroProto(resp) {
		return errors.New("bug: response proto must be zero value")
	}

	o := defaultSendRecvOpts(pID)
	for _, opt := range opts {
		opt(&o)
	}

	// Circuit relay connections are transient
	s, err := tcpNode.NewStream(network.WithAllowLimitedConn(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "new stream", z.Any("protocols", o.protocols))
	}
	if err := s.SetDeadline(time.Now().Add(o.sendTimeout)); err != nil {
		return errors.Wrap(err, "set deadline")
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
		return errors.Wrap(err, "write request", z.Any("protocol", s.Protocol()))
	}

	if err := s.CloseWrite(); err != nil {
		return errors.Wrap(err, "close write", z.Any("protocol", s.Protocol()))
	}

	if err = reader.ReadMsg(resp); err != nil {
		return errors.Wrap(err, "read response", z.Any("protocol", s.Protocol()))
	}

	if err = s.Close(); err != nil {
		return errors.Wrap(err, "close stream", z.Any("protocol", s.Protocol()))
	}

	o.rttCallback(time.Since(t0))

	return nil
}

// Send sends a libp2p message synchronously. It implements SendFunc.
func Send(ctx context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message,
	opts ...SendRecvOption,
) error {
	o := defaultSendRecvOpts(protoID)
	for _, opt := range opts {
		opt(&o)
	}
	// Circuit relay connections are transient
	s, err := tcpNode.NewStream(network.WithAllowLimitedConn(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "tcpNode stream")
	}
	if err := s.SetDeadline(time.Now().Add(o.sendTimeout)); err != nil {
		return errors.Wrap(err, "set deadline")
	}

	writeFunc, ok := o.writersByProtocol[s.Protocol()]
	if !ok {
		return errors.New("no writer for protocol", z.Any("protocol", s.Protocol()))
	}

	if err = writeFunc(s).WriteMsg(msg); err != nil {
		return errors.Wrap(err, "write message", z.Any("protocol", s.Protocol()))
	}

	if err := s.Close(); err != nil {
		return errors.Wrap(err, "close stream", z.Any("protocol", s.Protocol()))
	}

	return nil
}

// protocolPrefix returns the common prefix of the provided protocol IDs.
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
