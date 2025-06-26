// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/protonil"
	"github.com/obolnetwork/charon/app/z"
)

// HandlerFunc abstracts the handler logic that processes a p2p received proto message
// and returns a response or false or an error.
type HandlerFunc func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error)

// RegisterHandlerFunc abstracts a function that registers a libp2p stream handler
// that reads a single protobuf request and returns an optional response.
type RegisterHandlerFunc func(logTopic string, p2pNode host.Host, protocol protocol.ID,
	zeroReq func() proto.Message, handlerFunc HandlerFunc, opts ...SendRecvOption,
)

// Interface assertions.
var _ RegisterHandlerFunc = RegisterHandler

// RegisterHandler registers a canonical proto request and response handler for the provided protocol.
// - The zeroReq function returns a zero request to unmarshal.
// - The handlerFunc is called with the unmarshalled request and returns either a response or false or an error.
// - The marshalled response is sent back if present.
// - The stream is always closed before returning.
func RegisterHandler(logTopic string, p2pNode host.Host, pID protocol.ID,
	zeroReq func() proto.Message, handlerFunc HandlerFunc, opts ...SendRecvOption,
) {
	o := defaultSendRecvOpts(pID)
	for _, opt := range opts {
		opt(&o)
	}

	matchProtocol := func(pID protocol.ID) bool {
		return o.readersByProtocol[pID] != nil
	}

	p2pNode.SetStreamHandlerMatch(protocolPrefix(o.protocols...), matchProtocol, func(s network.Stream) {
		t0 := time.Now()
		name := PeerName(s.Conn().RemotePeer())

		_ = s.SetReadDeadline(time.Now().Add(o.receiveTimeout))
		ctx, cancel := context.WithTimeout(context.Background(), o.receiveTimeout)
		ctx = log.WithTopic(ctx, logTopic)
		ctx = log.WithCtx(ctx,
			z.Str("peer", name),
			z.Any("protocol", s.Protocol()),
		)

		defer cancel()
		defer s.Close()

		writeFunc, ok := o.writersByProtocol[s.Protocol()]
		if !ok {
			log.Error(ctx, "LibP2P no writer for protocol", nil)
			return
		}

		readFunc, ok := o.readersByProtocol[s.Protocol()]
		if !ok {
			log.Error(ctx, "LibP2P no reader for protocol", nil)
			return
		}

		req := zeroReq()

		err := readFunc(s).ReadMsg(req)
		if IsRelayError(err) {
			return // Ignore relay errors.
		} else if netErr := net.Error(nil); errors.As(err, &netErr) && netErr.Timeout() {
			log.Error(ctx, "LibP2P read timeout", err, z.Any("duration", time.Since(t0)))
			return
		} else if err != nil {
			log.Error(ctx, "LibP2P read request", err, z.Any("duration", time.Since(t0)))
			return
		} else if err := protonil.Check(req); err != nil {
			log.Warn(ctx, "LibP2P received invalid proto", err)
			return
		}

		resp, ok, err := handlerFunc(ctx, s.Conn().RemotePeer(), req)
		if err != nil {
			log.Error(ctx, "LibP2P handle stream error", err, z.Any("duration", time.Since(t0)))
			return
		}

		if !ok {
			return
		}

		if err := writeFunc(s).WriteMsg(resp); IsRelayError(err) {
			return // Ignore relay errors.
		} else if err != nil {
			log.Error(ctx, "LibP2P write response", err)
			return
		}
	})
}
