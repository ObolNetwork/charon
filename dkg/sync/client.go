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

	"github.com/libp2p/go-libp2p-core/host"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

type Result struct {
	timestamp string
	error     string
}

type Client struct {
	ctx       context.Context
	onFailure func()
	tcpNode   host.Host
	peer      p2p.Peer
	result    <-chan Result
}

// AwaitConnected blocks until the connection with the server has been established or returns an error.
func (*Client) AwaitConnected() error {
	return nil
}

// Shutdown sends a shutdown message to the peer indicating it has successfully completed.
// It closes the connection and returns after receiving the subsequent MsgSyncResponse.
// It may only be called after AwaitConnected.
func (*Client) Shutdown() error {
	return nil
}

// NewClient starts a goroutine that establishes a long lived connection to a p2p server and returns a new Client instance.
func NewClient(ctx context.Context, tcpNode host.Host, server p2p.Peer, hashSig []byte, onFailure func()) Client {
	s, err := tcpNode.NewStream(ctx, server.ID, syncProtoID)
	if err != nil {
		log.Error(ctx, "Open new stream with server", err)
		ch := make(chan Result, 1)
		ch <- Result{error: err.Error()}
		close(ch)

		return Client{
			ctx:       ctx,
			onFailure: onFailure,
			tcpNode:   tcpNode,
			peer:      server,
			result:    ch,
		}
	}

	ctx, cancel := context.WithCancel(ctx)

	out := make(chan Result)
	go func() {
		defer close(out)
		defer cancel()

		for ctx.Err() == nil {
			msg := &pb.MsgSync{
				Timestamp:     timestamppb.Now(),
				HashSignature: hashSig,
				Shutdown:      false,
			}

			b, err := proto.Marshal(msg)
			if err != nil {
				log.Error(ctx, "Marshal msg", err)
				return
			}

			if _, err = s.Write(b); err != nil {
				log.Error(ctx, "Write msg to stream", err)
				return
			}

			buf := bufio.NewReader(s)
			rb := make([]byte, MsgSize)
			// n is the number of bytes read from buffer, if n < MsgSize the other bytes will be 0
			n, err := buf.Read(rb)
			if err != nil {
				log.Error(ctx, "Read server response from stream", err)
				return
			}

			// Number of bytes that are read are the most important
			rb = rb[:n]

			resp := new(pb.MsgSyncResponse)
			if err = proto.Unmarshal(rb, resp); err != nil {
				log.Error(ctx, "Unmarshal server response", err)
			}

			log.Info(ctx, "Server response", z.Any("response", resp.SyncTimestamp))

			if ctx.Err() != nil {
				return
			}

			select {
			case out <- Result{timestamp: resp.SyncTimestamp.String(), error: resp.Error}:
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
		peer:      server,
		result:    out,
	}
}
