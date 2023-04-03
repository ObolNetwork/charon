// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const protocolID = "/charon/dkg/sync/1.0.0/"

// Protocols returns the list of supported Protocols in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID}
}

// NewServer returns a new Server instance.
func NewServer(tcpNode host.Host, allCount int, defHash []byte, version string) *Server {
	return &Server{
		defHash:   defHash,
		tcpNode:   tcpNode,
		allCount:  allCount,
		shutdown:  make(map[peer.ID]struct{}),
		connected: make(map[peer.ID]struct{}),
		version:   version,
	}
}

// Server implements the server side of the sync protocol. It accepts connections from clients, verifies
// definition hash signatures, and supports waiting for shutdown by all clients.
type Server struct {
	// Immutable state
	tcpNode  host.Host
	defHash  []byte
	version  string
	allCount int // Excluding self

	// Mutable state
	mu        sync.Mutex
	shutdown  map[peer.ID]struct{}
	connected map[peer.ID]struct{}
	err       error // To return error and exit anywhere in the server flow
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
			if err := s.Error(); err != nil {
				return err
			}

			if s.isAllConnected() {
				return nil
			}
		}
	}
}

// setErrored sets the shared error state for the server.
func (s *Server) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.err = err
}

// Error returns the shared error state for the server.
func (s *Server) Error() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.err
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
	defer s.clearConnected(pID)

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

		if err := s.validReq(pubkey, msg); err != nil {
			s.setError(errors.Wrap(err, "invalid sync message", z.Str("peer", p2p.PeerName(pID))))
			resp.Error = err.Error()
		} else if !s.isConnected(pID) {
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

// validReq returns an error message and false if the request version or definition hash are invalid.
// Else it returns true or an error.
func (s *Server) validReq(pubkey crypto.PubKey, msg *pb.MsgSync) error {
	if msg.Version != s.version {
		return fmt.Errorf("mismatching charon version; expect=%s, got=%s", s.version, msg.Version) //nolint: wrapcheck,forbidigo // Use stdlib errors when sending over the wire.
	}

	ok, err := pubkey.Verify(s.defHash, msg.HashSignature)
	if err != nil { // Note: libp2p verify does another hash of defHash.
		return errors.Wrap(err, "error verifying definition hash signature")
	} else if !ok {
		return errors.New("invalid definition hash signature")
	}

	return nil
}

// Start registers sync protocol with the libp2p host.
func (s *Server) Start(ctx context.Context) {
	s.tcpNode.SetStreamHandler(protocolID, func(stream network.Stream) {
		ctx := log.WithCtx(ctx, z.Str("peer", p2p.PeerName(stream.Conn().RemotePeer())))
		err := s.handleStream(ctx, stream)
		if isRelayError(err) { // Relay errors are expected
			log.Debug(ctx, "Relay error serving sync protocol", z.Str("err", err.Error()))
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
