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
	"context"
	"io/ioutil"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// NewClient starts a goroutine that establishes a long lived connection to a p2p server and returns a new Client instance.
func NewClient(ctx context.Context, tcpNode host.Host, server p2p.Peer, hash []byte, onFailure func(), ch chan *pb.MsgSyncResponse) Client {
	go func() {
		s, err := tcpNode.NewStream(ctx, server.ID, syncProtoID)
		if err != nil {
			log.Error(ctx, "Open new stream with server", err)
		}
		defer s.Close()

		msg := &pb.MsgSync{
			Timestamp:     timestamppb.Now(),
			HashSignature: hash,
			Shutdown:      false,
		}

		b, err := proto.Marshal(msg)
		if err != nil {
			log.Error(ctx, "Marshal msg", err)
		}

		if _, err = s.Write(b); err != nil {
			log.Error(ctx, "Write msg to stream", err)
		}

		// Read Server's response
		out, err := ioutil.ReadAll(s)
		if err != nil {
			log.Error(ctx, "Read server response", err)
			return
		}

		resp := new(pb.MsgSyncResponse)
		if err = proto.Unmarshal(out, resp); err != nil {
			log.Error(ctx, "Unmarshal server response", err)
		}

		log.Info(ctx, "Server response", z.Any("response", resp.SyncTimestamp))
		ch <- resp
	}()

	return Client{
		ctx:       ctx,
		onFailure: onFailure,
		tcpNode:   tcpNode,
		peer:      server,
	}
}

type Client struct {
	ctx          context.Context
	onFailure    func()
	tcpNode      host.Host
	peer         p2p.Peer
	serverStream network.Stream
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
