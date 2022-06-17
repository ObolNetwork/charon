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
//nolint:revive
package sync

import (
	"context"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/log"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

func NewClient(ctx context.Context, tcpNode host.Host, server p2p.Peer, hash []byte, onFailure func()) Client {
	go func() {
		str, err := tcpNode.NewStream(ctx, server.ID, ID)
		if err != nil {
			log.Error(ctx, "Open new stream with server", err)
		}
		defer str.Close()

		msg := &pb.MsgSync{
			Timestamp:     timestamppb.Now(),
			HashSignature: hash,
			Shutdown:      false,
		}

		b, err := proto.Marshal(msg)
		if err != nil {
			log.Error(ctx, "Marshal msg", err)
		}

		n, err := str.Write(b)
		if err != nil && n != 0 {
			log.Error(ctx, "Write msg to stream", err)
		}
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

func (c *Client) AwaitConnected() error {
	return nil
}

func (c *Client) Shutdown() error {
	return nil
}
