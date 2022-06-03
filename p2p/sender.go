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

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
)

// SendAsync sends a libp2p message and logs a warning on error.
//   Usage: go p2p.SendAsync(ctx, tcpNode, protoId, peerId, msg)
func SendAsync(ctx context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message) {
	err := sendMsg(ctx, tcpNode, protoID, peerID, msg)
	if err != nil {
		log.Warn(ctx, "Failed sending p2p message", err)
	}
}

func sendMsg(ctx context.Context, tcpNode host.Host, protoID protocol.ID, peerID peer.ID, msg proto.Message) error {
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
