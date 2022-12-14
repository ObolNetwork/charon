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
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// HandlerFunc abstracts the handler logic that processes a p2p received proto message
// and returns a response or false or an error.
type HandlerFunc func(ctx context.Context, peerID peer.ID, req proto.Message) (proto.Message, bool, error)

// RegisterHandlerFunc abstracts a function that registers a libp2p stream handler
// that reads a single protobuf request and returns an optional response.
type RegisterHandlerFunc func(logTopic string, tcpNode host.Host, protocol protocol.ID,
	zeroReq func() proto.Message, handlerFunc HandlerFunc,
)

// RegisterHandler registers a canonical proto request and response handler for the provided protocol.
// - The zeroReq function returns a zero request to unmarshal.
// - The handlerFunc is called with the unmarshalled request and returns either a response or false or an error.
// - The marshalled response is sent back if present.
// - The stream is always closed before returning.
func RegisterHandler(logTopic string, tcpNode host.Host, protocol protocol.ID,
	zeroReq func() proto.Message, handlerFunc HandlerFunc,
) {
	tcpNode.SetStreamHandler(protocol, func(s network.Stream) {
		t0 := time.Now()
		name := PeerName(s.Conn().RemotePeer())
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		ctx = log.WithTopic(ctx, logTopic)
		ctx = log.WithCtx(ctx,
			z.Str("peer", name),
			z.Str("protocol", string(protocol)),
		)
		defer cancel()
		defer s.Close()

		b, err := io.ReadAll(s)
		if IsRelayError(err) {
			return // Ignore relay errors.
		} else if err != nil {
			log.Error(ctx, "LibP2P read request", err, z.Any("duration", time.Since(t0)))
			return
		}

		req := zeroReq()
		if err := proto.Unmarshal(b, req); err != nil {
			log.Error(ctx, "LibP2P unmarshal request", err)
			return
		}

		networkRXCounter.WithLabelValues(name, string(s.Protocol())).Add(float64(len(b)))

		resp, ok, err := handlerFunc(ctx, s.Conn().RemotePeer(), req)
		if err != nil {
			log.Error(ctx, "LibP2P handle stream error", err, z.Any("duration", time.Since(t0)))
			return
		}

		if !ok {
			return
		}

		b, err = proto.Marshal(resp)
		if err != nil {
			log.Error(ctx, "LibP2P marshall response", err)
			return
		}

		if _, err := s.Write(b); IsRelayError(err) {
			return // Ignore relay errors.
		} else if err != nil {
			log.Error(ctx, "LibP2P write response", err)
			return
		}

		networkTXCounter.WithLabelValues(name, string(s.Protocol())).Add(float64(len(b)))
	})
}
