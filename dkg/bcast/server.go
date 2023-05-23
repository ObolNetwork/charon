// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"bytes"
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// newServer creates a new reliable-broadcast server.
func newServer(tcpNode host.Host, signFunc signFunc, verifyFunc verifyFunc) *server {
	s := &server{
		callbacks:  map[string]Callback{},
		signFunc:   signFunc,
		verifyFunc: verifyFunc,
		dedup:      make(map[dedupKey][]byte),
	}

	p2p.RegisterHandler("bcast", tcpNode, protocolIDSig,
		func() proto.Message { return new(pb.BCastSigRequest) },
		s.handleSigRequest,
		p2p.WithDelimitedProtocol(protocolIDSig),
	)

	p2p.RegisterHandler("bcast", tcpNode, protocolIDMsg,
		func() proto.Message { return new(pb.BCastMessage) },
		s.handleMessage,
		p2p.WithDelimitedProtocol(protocolIDMsg),
	)

	return s
}

// dedupKey ensures only a single hash is signed per peer and message ID.
// Ie. byzantine peer cannot broadcast different hashes for the same message ID.
type dedupKey struct {
	PeerID peer.ID
	MsgID  string
}

// server is a reliable-broadcast server.
type server struct {
	callbacksMutex sync.Mutex
	callbacks      map[string]Callback

	signFunc   signFunc
	verifyFunc verifyFunc

	mu    sync.Mutex
	dedup map[dedupKey][]byte // map[dedupKey]hash
}

func (s *server) getCallback(msgID string) (Callback, bool) {
	s.callbacksMutex.Lock()
	defer s.callbacksMutex.Unlock()

	fn, found := s.callbacks[msgID]

	return fn, found
}

func (s *server) registerCallback(msgID string, cb Callback) {
	s.callbacksMutex.Lock()
	defer s.callbacksMutex.Unlock()

	s.callbacks[msgID] = cb
}

func (s *server) dedupHash(pID peer.ID, msgID string, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := dedupKey{PeerID: pID, MsgID: msgID}

	prevHash, ok := s.dedup[key]
	if ok && !bytes.Equal(prevHash, hash) {
		return errors.New("duplicate ID, mismatching hash")
	}

	s.dedup[key] = hash

	return nil
}

func (s *server) handleSigRequest(_ context.Context, pID peer.ID, m proto.Message) (proto.Message, bool, error) {
	req, ok := m.(*pb.BCastSigRequest)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	// Only sign once per peer and message ID.
	if err := s.dedupHash(pID, req.Id, req.Hash); err != nil {
		return nil, false, errors.Wrap(err, "dedup")
	}

	sig, err := s.signFunc(req.Id, req.Hash)
	if err != nil {
		return nil, false, errors.Wrap(err, "sign hash")
	}

	return &pb.BCastSigResponse{Id: req.Id, Signature: sig}, true, nil
}

func (s *server) handleMessage(ctx context.Context, pID peer.ID, m proto.Message) (proto.Message, bool, error) {
	msg, ok := m.(*pb.BCastMessage)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	if err := s.verifyFunc(msg.Id, msg.Message, msg.Signatures); err != nil {
		return nil, false, errors.Wrap(err, "verify signatures")
	}

	inner, err := msg.Message.UnmarshalNew()
	if err != nil {
		return nil, false, errors.Wrap(err, "unmarshal any")
	}

	fn, found := s.getCallback(msg.Id)
	if !found {
		return nil, false, errors.New("unknown message id", z.Str("message_id", msg.Id))
	}

	if err := fn(ctx, pID, msg.Id, inner); err != nil {
		return nil, false, errors.Wrap(err, "callback")
	}

	return nil, true, nil
}
