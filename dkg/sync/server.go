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
	"io"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const ID = "dkg_v1.0"

func NewServer(ctx context.Context, tcpNode host.Host, _ []p2p.Peer, hash []byte, onFailure func(), ch chan *pb.MsgSync) *Server {
	server := &Server{
		ctx:     ctx,
		tcpNode: tcpNode,
		// peers:      peers,
		onFailure:  onFailure,
		clientMsgs: make(chan *pb.MsgSync),
	}

	server.tcpNode.SetStreamHandler(ID, func(stream network.Stream) {
		defer stream.Close()

		b, err := io.ReadAll(stream)
		if err != nil {
			log.Error(ctx, "Read client msg from stream", err)
		}

		msg := new(pb.MsgSync)
		if err = proto.Unmarshal(b, msg); err != nil {
			log.Error(ctx, "Unmarshal client msg", err)
		}

		ch <- msg
	})

	return server
}

type Server struct {
	ctx        context.Context
	onFailure  func()
	tcpNode    host.Host
	peers      []p2p.Peer
	clientMsgs chan *pb.MsgSync
}

func (s *Server) AwaitAllConnected() error {
	return nil
}

func (s *Server) AwaitAllShutdown() error {
	return nil
}
