// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"io"
	"sync"
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
	senderHysteresis = 3
	senderBuffer     = senderHysteresis + 1
	maxMsgSize       = 128 << 20 // 128MB
)

// p2pFuzzEnabled is used to enable peer to peer fuzzing in charon.
var p2pFuzzEnabled bool

func EnableP2PFuzz() {
	p2pFuzzEnabled = true
}

// SendFunc is an abstract function responsible for sending libp2p messages.
type SendFunc func(context.Context, host.Host, protocol.ID, peer.ID, proto.Message, ...SendRecvOption) error

// SendReceiveFunc is an abstract function responsible for sending a libp2p request and returning
// (populating) a libp2p response.
type SendReceiveFunc func(ctx context.Context, tcpNode host.Host, peerID peer.ID,
	req, resp proto.Message, protocol protocol.ID, opts ...SendRecvOption) error

var (
	_ SendFunc = Send
	_ SendFunc = new(Sender).SendAsync
)

type peerState struct {
	failing bool
	buffer  []error
}

// Sender provides an API for sending libp2p messages, both synchronous and asynchronous.
// It also provides log filtering for async sending, mitigating
// error storms when peers are down.
type Sender struct {
	states sync.Map // map[peer.ID]peerState
}

// addResult adds the result of sending a p2p message to the internal state and possibly logs a status change.
func (s *Sender) addResult(ctx context.Context, peerID peer.ID, err error) {
	var state peerState
	if val, ok := s.states.Load(peerID); ok {
		state = val.(peerState)
	}

	state.buffer = append(state.buffer, err)
	if len(state.buffer) > senderBuffer { // Trim buffer
		state.buffer = state.buffer[len(state.buffer)-senderBuffer:]
	}

	failure := err != nil
	success := !failure

	if success && state.failing {
		// See if we have senderHysteresis successes i.o.t. change state to success.
		full := len(state.buffer) == senderBuffer
		oldestFailure := state.buffer[0] != nil
		othersSuccess := true
		for i := 1; i < len(state.buffer); i++ {
			if state.buffer[i] != nil {
				othersSuccess = false
				break
			}
		}

		if full && oldestFailure && othersSuccess {
			state.failing = false
			log.Info(ctx, "P2P sending recovered", z.Str("peer", PeerName(peerID)))
		}
	} else if failure && (len(state.buffer) == 1 || !state.failing) {
		// First attempt failed or state changed to failing

		if _, ok := dialErrMsgs(err); !ok { // Only log non-dial errors
			log.Warn(ctx, "P2P sending failing", err, z.Str("peer", PeerName(peerID)))
		}

		state.failing = true
	}

	s.states.Store(peerID, state) // Note there is a race if two results for the same peer is added at the same time, but this isn't critical.
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

// WithFuzzReaderWriter returns an option that sets a fuzz reader writer to all the protocols if p2p fuzz is enabled.
//
// If p2p fuzz is enabled, this option sets a fuzz reader writer for each protocol in the provided sendRecvOpts.
// The fuzz reader writer is responsible for creating a customized reader and writer for each network stream
// associated with a specific protocol. The reader and writer implement the pbio.Reader and pbio.Writer interfaces,
// respectively, from the "pbio" package.
func WithFuzzReaderWriter() func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		if !p2pFuzzEnabled {
			return
		}

		for _, pID := range opts.protocols {
			opts.writersByProtocol[pID] = func(s network.Stream) pbio.Writer {
				return &fuzzReaderWriter{w: pbio.NewDelimitedWriter(s)}
			}
			opts.readersByProtocol[pID] = func(s network.Stream) pbio.Reader {
				return &fuzzReaderWriter{}
			}
		}
	}
}

// defaultSendRecvOpts returns the default sendRecvOpts, it uses the legacy writers and noop rtt callback.
func defaultSendRecvOpts(pID protocol.ID) sendRecvOpts {
	return sendRecvOpts{
		protocols: []protocol.ID{pID},
		writersByProtocol: map[protocol.ID]func(s network.Stream) pbio.Writer{
			pID: func(s network.Stream) pbio.Writer { return legacyReadWriter{s} },
		},
		readersByProtocol: map[protocol.ID]func(s network.Stream) pbio.Reader{
			pID: func(s network.Stream) pbio.Reader { return legacyReadWriter{s} },
		},
		rttCallback: func(time.Duration) {},
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
	s, err := tcpNode.NewStream(network.WithUseTransient(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "new stream", z.Any("protocols", o.protocols))
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

	zeroResp := proto.Clone(resp)

	if err = reader.ReadMsg(resp); err != nil {
		return errors.Wrap(err, "read response", z.Any("protocol", s.Protocol()))
	}

	// TODO(corver): Remove this once we only use length-delimited protocols.
	//  This was added since legacy stream delimited readers couldn't distinguish between
	//  no response and a zero response.
	if proto.Equal(resp, zeroResp) {
		return errors.New("no or zero response received", z.Any("protocol", s.Protocol()))
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
	s, err := tcpNode.NewStream(network.WithUseTransient(ctx, ""), peerID, o.protocols...)
	if err != nil {
		return errors.Wrap(err, "tcpNode stream")
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

// legacyReadWriter implements pbio.Reader and pbio.Writer without length delimited encoding.
type legacyReadWriter struct {
	stream network.Stream
}

// WriteMsg writes a protobuf message to the stream.
func (w legacyReadWriter) WriteMsg(m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	_, err = w.stream.Write(b)

	return err
}

// ReadMsg reads a single protobuf message from the whole stream.
// The stream must be closed after the message was sent.
func (w legacyReadWriter) ReadMsg(m proto.Message) error {
	b, err := io.ReadAll(w.stream)
	if err != nil {
		return errors.Wrap(err, "read proto")
	}

	if err = proto.Unmarshal(b, m); err != nil {
		return errors.Wrap(err, "unmarshal proto")
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
