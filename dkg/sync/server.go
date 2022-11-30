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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const (
	protocolID    = "/charon/dkg/sync/1.0.0/"
	errInvalidSig = "invalid signature"
)

// NewServer returns a new Server instance.
func NewServer(tcpNode host.Host, allCount int, defHash []byte) *Server {
	return &Server{
		defHash:   defHash,
		tcpNode:   tcpNode,
		allCount:  allCount,
		shutdown:  make(map[peer.ID]struct{}),
		connected: make(map[peer.ID]struct{}),
	}
}

// Server implements the server side of the sync protocol. It accepts connections from clients, verifies
// definition hash signatures, and supports waiting for shutdown by all clients.
type Server struct {
	mu          sync.Mutex
	shutdown    map[peer.ID]struct{}
	connected   map[peer.ID]struct{}
	defHash     []byte
	allCount    int // Excluding self
	tcpNode     host.Host
	errResponse bool // To return error and exit anywhere in the server flow
}

// AwaitAllConnected blocks until all peers have established a connection with this server or returns an error.
func (s *Server) AwaitAllConnected(ctx context.Context) error {
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if s.isError() {
				return errors.New("unexpected error occurred")
			}

			if s.isAllConnected() {
				return nil
			}
		}
	}
}

// isError checks if there was any error in between the server flow.
func (s *Server) isError() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.errResponse
}

// AwaitAllShutdown blocks until all peers have successfully shutdown or returns an error.
// It may only be called after AwaitAllConnected.
func (s *Server) AwaitAllShutdown(ctx context.Context) error {
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if s.isAllShutdown() {
				return nil
			}
		}
	}
}

// isConnected returns the shared connected state for the peer.
func (s *Server) isConnected(pID peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.connected[pID]

	return ok
}

// setConnected sets the shared connected state for the peer.
func (s *Server) setConnected(pID peer.ID) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.connected[pID] = struct{}{}

	return len(s.connected)
}

// setShutdown sets the shared shutdown state for the peer.
func (s *Server) setShutdown(pID peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.shutdown[pID] = struct{}{}
}

// isAllConnected returns if all expected peers are connected.
func (s *Server) isAllConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.connected) == s.allCount
}

// isAllShutdown returns if all expected peers are shutdown.
func (s *Server) isAllShutdown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.shutdown) == s.allCount
}

// clearConnected clears connected state for the given peer.
func (s *Server) clearConnected(pID peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.connected, pID)
}

// handleStream serves a new long-lived client connection.
func (s *Server) handleStream(ctx context.Context, stream network.Stream) error {
	defer stream.Close()

	pID := stream.Conn().RemotePeer()
	defer func() {
		s.clearConnected(pID)

		if ctx.Err() == nil {
			log.Info(ctx, "Peer connection dropped!", z.Str("peer", p2p.PeerName(pID)),
				z.Str("local_peer", p2p.PeerName(s.tcpNode.ID())))
		}
	}()

	pubkey, err := pID.ExtractPublicKey()
	if err != nil {
		return errors.Wrap(err, "extract pubkey")
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Read next sync message
		msg := new(pb.MsgSync)
		if err := readSizedProto(stream, msg); err != nil {
			return err
		}

		// Prep response
		resp := &pb.MsgSyncResponse{
			SyncTimestamp: msg.Timestamp,
		}

		// Verify definition hash
		ok, err := pubkey.Verify(s.defHash, msg.HashSignature)
		if err != nil {
			return errors.Wrap(err, "verify sig hash")
		} else if !ok {
			resp.Error = errInvalidSig

			s.mu.Lock()
			s.errResponse = true
			s.mu.Unlock()

			log.Error(ctx, "Received mismatching cluster definition hash from peer", nil)
		} else if ok && !s.isConnected(pID) {
			count := s.setConnected(pID)
			log.Info(ctx, fmt.Sprintf("Connected to peer %d of %d", count, s.allCount))
		}

		// Write response message
		if err := writeSizedProto(stream, resp); err != nil {
			return err
		}

		if msg.Shutdown {
			s.setShutdown(pID)
			return nil
		}
	}
}

// Start registers sync protocol with the libp2p host.
func (s *Server) Start(ctx context.Context) {
	s.tcpNode.SetStreamHandler(protocolID, func(stream network.Stream) {
		if ctx.Err() != nil {
			return
		}

		ctx = log.WithCtx(ctx, z.Str("peer", p2p.PeerName(stream.Conn().RemotePeer())))
		err := s.handleStream(ctx, stream)
		if isRelayError(err) {
			log.Debug(ctx, "Relay connection dropped, expect reconnect")
		} else if err != nil {
			log.Warn(ctx, "Error serving sync protocol", err)
		}
	})
}

// writeSizedProto writes a size prefixed proto message.
func writeSizedProto(writer io.Writer, msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	size := int64(len(buf))
	err = binary.Write(writer, binary.LittleEndian, size)
	if err != nil {
		return errors.Wrap(err, "read size")
	}

	n, err := writer.Write(buf)
	if err != nil {
		return errors.Wrap(err, "write message")
	} else if int64(n) != size {
		return errors.New("unexpected message length")
	}

	return nil
}

// readSizedProto reads a size prefixed proto message.
func readSizedProto(reader io.Reader, msg proto.Message) error {
	var size int64
	err := binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return errors.Wrap(err, "read size")
	}

	buf := make([]byte, size)
	n, err := reader.Read(buf)
	if err != nil {
		return errors.Wrap(err, "read buffer")
	} else if int64(n) != size {
		return errors.New("unexpected message length")
	}

	err = proto.Unmarshal(buf, msg)
	if err != nil {
		return errors.Wrap(err, "unmarshal proto")
	}

	return nil
}
