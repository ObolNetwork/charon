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

package sync

import (
	"bufio"
	"context"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

type result struct {
	rtt       time.Duration
	timestamp string
	error     error
}

type Client struct {
	ctx       context.Context
	onFailure func()
	tcpNode   host.Host
	server    p2p.Peer
	results   chan result
}

// AwaitConnected blocks until the connection with the server has been established or returns an error.
func (c *Client) AwaitConnected() error {
	for res := range c.results {
		if errors.Is(res.error, errors.New(InvalidSig)) {
			return errors.New("invalid cluster definition")
		} else if res.error == nil {
			// We are connected
			break
		}
	}

	log.Info(c.ctx, "Client connected to Server 🎉", z.Any("client", p2p.PeerName(c.tcpNode.ID())))

	return nil
}

// Shutdown sends a shutdown message to the server indicating it has successfully completed.
// It closes the connection and returns after receiving the subsequent MsgSyncResponse.
// It may only be called after AwaitConnected.
func (*Client) Shutdown() error {
	return nil
}

// sendHashSignature sends MsgSync with signature of definition to server and receives response from server.
func sendHashSignature(ctx context.Context, hashSig []byte, s network.Stream) result {
	before := time.Now()
	msg := &pb.MsgSync{
		Timestamp:     timestamppb.Now(),
		HashSignature: hashSig,
		Shutdown:      false,
	}

	wb, err := proto.Marshal(msg)
	if err != nil {
		log.Error(ctx, "Marshal msg", err)
		return result{error: err}
	}

	if _, err = s.Write(wb); err != nil {
		log.Error(ctx, "Write msg to stream", err)
		return result{error: err}
	}

	buf := bufio.NewReader(s)
	rb := make([]byte, MsgSize)
	// n is the number of bytes read from buffer, if n < MsgSize the other bytes will be 0
	n, err := buf.Read(rb)
	if err != nil {
		log.Error(ctx, "Read server response from stream", err)
		return result{error: err}
	}

	// The first `n` bytes that are read are the most important
	rb = rb[:n]

	resp := new(pb.MsgSyncResponse)
	if err = proto.Unmarshal(rb, resp); err != nil {
		log.Error(ctx, "Unmarshal server response", err)
		return result{error: err}
	}

	if resp.Error != "" {
		return result{error: errors.New(resp.Error)}
	}

	log.Debug(ctx, "Server response", z.Any("response", resp.SyncTimestamp))

	return result{
		rtt:       time.Since(before),
		timestamp: resp.SyncTimestamp.String(),
	}
}

// NewClient starts a goroutine that establishes a long lived connection to a p2p server and returns a new Client instance.
// TODO(dhruv): call onFailure on permanent failure.
func NewClient(ctx context.Context, tcpNode host.Host, server p2p.Peer, hashSig []byte, onFailure func()) Client {
	s, err := tcpNode.NewStream(ctx, server.ID, syncProtoID)
	if err != nil {
		log.Error(ctx, "Open new stream with server", err)
		ch := make(chan result, 1)
		ch <- result{error: err}
		close(ch)

		return Client{
			ctx:       ctx,
			onFailure: onFailure,
			tcpNode:   tcpNode,
			server:    server,
			results:   ch,
		}
	}

	ctx, cancel := context.WithCancel(ctx)

	out := make(chan result)
	go func() {
		defer close(out)
		defer cancel()

		for ctx.Err() == nil {
			res := sendHashSignature(ctx, hashSig, s)

			if ctx.Err() != nil {
				return
			}

			if res.error == nil {
				tcpNode.Peerstore().RecordLatency(server.ID, res.rtt)
			}

			select {
			case out <- res:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		//nolint:errcheck
		s.Reset()
	}()

	return Client{
		ctx:       ctx,
		onFailure: onFailure,
		tcpNode:   tcpNode,
		server:    server,
		results:   out,
	}
}
