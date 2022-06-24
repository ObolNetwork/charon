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

// Package sync provides Client and Server APIs that ensures robust network connectivity between all peers in the DKG.
// It supports cluster_definition verification, soft shutdown and reconnect on connection loss.
package sync

import (
	"bufio"
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const (
	syncProtoID = "dkg_sync_v1.0"
	MsgSize     = 128
	InvalidSig  = "Invalid Signature"
)

type Server struct {
	mu            sync.Mutex
	ctx           context.Context
	onFailure     func()
	tcpNode       host.Host
	peers         []p2p.Peer
	dedupResponse map[peer.ID]bool
	receiveChan   chan result
}

// AwaitAllConnected blocks until all peers have established a connection with this server or returns an error.
func (s *Server) AwaitAllConnected() error {
	var msgs []result
	for len(msgs) < len(s.peers) {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case msg := <-s.receiveChan:
			msgs = append(msgs, msg)
		}
	}

	log.Info(s.ctx, "All Clients Connected 🎉", z.Any("clients", len(msgs)))

	return nil
}

// AwaitAllShutdown blocks until all peers have successfully shutdown or returns an error.
// It may only be called after AwaitAllConnected.
func (*Server) AwaitAllShutdown() error {
	return nil
}

// NewServer registers a Stream Handler and returns a new Server instance.
func NewServer(ctx context.Context, tcpNode host.Host, peers []p2p.Peer, defHash []byte, onFailure func()) *Server {
	server := &Server{
		ctx:           ctx,
		tcpNode:       tcpNode,
		peers:         peers,
		onFailure:     onFailure,
		dedupResponse: make(map[peer.ID]bool),
		receiveChan:   make(chan result, len(peers)),
	}

	knownPeers := make(map[peer.ID]bool)
	for _, peer := range peers {
		knownPeers[peer.ID] = true
	}

	server.tcpNode.SetStreamHandler(syncProtoID, func(s network.Stream) {
		defer s.Close()

		// TODO(dhruv): introduce timeout to break the loop
		for {
			before := time.Now()
			pID := s.Conn().RemotePeer()
			if !knownPeers[pID] {
				// Ignoring unknown peer
				log.Warn(ctx, "Ignoring unknown client", nil, z.Any("client", p2p.PeerName(pID)))
				return
			}

			buf := bufio.NewReader(s)
			b := make([]byte, MsgSize)
			// n is the number of bytes read from buffer, if n < MsgSize the other bytes will be 0
			n, err := buf.Read(b)
			if err != nil {
				log.Error(ctx, "Read client msg from stream", err, z.Any("client", p2p.PeerName(pID)))
				return
			}

			// The first `n` bytes that are read are the most important
			b = b[:n]

			msg := new(pb.MsgSync)
			if err := proto.Unmarshal(b, msg); err != nil {
				log.Error(ctx, "Unmarshal client msg", err)
				return
			}

			log.Debug(ctx, "Message received from client", z.Any("client", p2p.PeerName(pID)))

			pubkey, err := pID.ExtractPublicKey()
			if err != nil {
				log.Error(ctx, "Get client public key", err)
				return
			}

			ok, err := pubkey.Verify(defHash, msg.HashSignature)
			if err != nil {
				log.Error(ctx, "Verify defHash signature", err)
				return
			}

			resp := &pb.MsgSyncResponse{
				SyncTimestamp: msg.Timestamp,
				Error:         "",
			}

			if !ok {
				resp.Error = InvalidSig
			}

			resBytes, err := proto.Marshal(resp)
			if err != nil {
				log.Error(ctx, "Marshal server response", err)
				return
			}

			_, err = s.Write(resBytes)
			if err != nil {
				log.Error(ctx, "Send response to client", err, z.Any("client", p2p.PeerName(pID)))
				return
			}

			if server.dedupResponse[pID] {
				log.Debug(ctx, "Ignoring duplicate message", z.Any("client", p2p.PeerName(pID)))
				continue
			}

			if resp.Error == "" && !server.dedupResponse[pID] {
				// TODO(dhruv): This is temporary solution to avoid race condition of concurrent writes to map, figure out something permanent.
				server.mu.Lock()
				server.dedupResponse[pID] = true
				server.mu.Unlock()

				server.receiveChan <- result{
					rtt:       time.Since(before),
					timestamp: msg.Timestamp.String(),
				}
			}

			log.Debug(ctx, "Send response to client", z.Any("client", p2p.PeerName(pID)))
		}
	})

	return server
}
