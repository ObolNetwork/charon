// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	senderHysteresis = 3
	senderBuffer     = senderHysteresis + 1
)

// SendFunc is an abstract function responsible for sending libp2p messages.
type SendFunc func(context.Context, host.Host, protocol.ID, peer.ID, proto.Message) error

// SendReceiveFunc is an abstract function responsible for sending a libp2p request and returning
// (populating) a libp2p response.
type SendReceiveFunc func(ctx context.Context, tcpNode host.Host, peerID peer.ID,
	req, resp proto.Message, protocol protocol.ID, opts ...func(*sendRecvOpts)) error

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
func (s *Sender) SendAsync(parent context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message) error {
	go func() {
		// Clone the context since parent context may be closed soon.
		ctx := log.CopyFields(context.Background(), parent)
		ctx = log.WithCtx(ctx, z.Str("protocol", string(protoID)))

		err := withRelayRetry(func() error {
			return Send(ctx, tcpNode, protoID, peerID, msg)
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
	protocol protocol.ID, opts ...func(*sendRecvOpts),
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

type sendRecvOpts struct {
	pids        []protocol.ID
	rttCallback func(time.Duration)
}

// WithSendReceiveRTT returns an option for SendReceive that sets a callback for the RTT.
func WithSendReceiveRTT(callback func(time.Duration)) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.rttCallback = callback
	}
}

// WithSendReceiveProtocols returns an option for SendReceive that sets the protocols to use.
// Note this overrides the protocol provided in the SendReceive.
func WithSendReceiveProtocols(pids ...protocol.ID) func(*sendRecvOpts) {
	return func(opts *sendRecvOpts) {
		opts.pids = pids
	}
}

// SendReceive sends and receives a libp2p request and response message
// pair synchronously and then closes the stream.
// The provided response proto will be populated if err is nil.
// It implements SendReceiveFunc.
func SendReceive(ctx context.Context, tcpNode host.Host, peerID peer.ID,
	req, resp proto.Message, pID protocol.ID, opts ...func(*sendRecvOpts),
) error {
	o := sendRecvOpts{
		pids:        []protocol.ID{pID},
		rttCallback: func(time.Duration) {},
	}
	for _, opt := range opts {
		opt(&o)
	}
	ctx = log.WithCtx(ctx, z.Any("protocol", o.pids))

	b, err := proto.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	// Circuit relay connections are transient
	s, err := tcpNode.NewStream(network.WithUseTransient(ctx, ""), peerID, o.pids...)
	if err != nil {
		return errors.Wrap(err, "new stream", z.Any("protocols", o.pids))
	}

	t0 := time.Now()
	if _, err = s.Write(b); err != nil {
		return errors.Wrap(err, "write request")
	}

	if err := s.CloseWrite(); err != nil {
		return errors.Wrap(err, "close write")
	}

	b, err = io.ReadAll(s)
	if err != nil {
		return errors.Wrap(err, "read response")
	} else if len(b) == 0 {
		return errors.New("peer errored, no response")
	}

	if err = proto.Unmarshal(b, resp); err != nil {
		return errors.Wrap(err, "unmarshal response")
	}

	if err = s.Close(); err != nil {
		return errors.Wrap(err, "unmarshal response")
	}

	o.rttCallback(time.Since(t0))

	return nil
}

// Send sends a libp2p message synchronously. It implements SendFunc.
func Send(ctx context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message) error {
	b, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	// Circuit relay connections are transient
	s, err := tcpNode.NewStream(network.WithUseTransient(ctx, ""), peerID, protoID)
	if err != nil {
		return errors.Wrap(err, "tcpNode stream")
	}

	_, err = s.Write(b)
	if err != nil {
		return errors.Wrap(err, "tcpNode write")
	}

	if err := s.Close(); err != nil {
		return errors.Wrap(err, "tcpNode close")
	}

	return nil
}

// ProtocolSupported returns whether the peer supports the protocol or whether this is unknown.
func ProtocolSupported(tcpNode host.Host, peerID peer.ID, protocolID protocol.ID) (supported bool, known bool) {
	// Check if peer supports this protocol.
	protocols, err := tcpNode.Peerstore().GetProtocols(peerID)
	if err != nil || len(protocols) == 0 {
		return false, false // Unknown
	}

	for _, p := range protocols {
		if p == string(protocolID) {
			return true, true // Supported
		}
	}

	return false, true // Not supported
}
