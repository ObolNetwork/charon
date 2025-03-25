// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
func newServer(tcpNode host.Host, signFunc signFunc, hashFunc hashFunc, verifyFunc verifyFunc) *server {
	s := &server{
		msgIDFuncs: map[string]messageIDFuncs{},
		signFunc:   signFunc,
		verifyFunc: verifyFunc,
		hashFunc:   hashFunc,
		dedup:      make(map[dedupKey][]byte),
	}

	p2p.RegisterHandler("bcast", tcpNode, protocolIDSig,
		func() proto.Message { return new(pb.BCastSigRequest) },
		s.handleSigRequest,
		p2p.WithReceiveTimeout(receiveTimeout),
	)

	p2p.RegisterHandler("bcast", tcpNode, protocolIDMsg,
		func() proto.Message { return new(pb.BCastMessage) },
		s.handleMessage,
		p2p.WithReceiveTimeout(receiveTimeout),
	)

	return s
}

// dedupKey ensures only a single hash is signed per peer and message ID.
// Ie. byzantine peer cannot broadcast different hashes for the same message ID.
type dedupKey struct {
	PeerID peer.ID
	MsgID  string
}

type messageIDFuncs struct {
	callback     Callback
	checkMessage CheckMessage
}

// server is a reliable-broadcast server.
type server struct {
	msgIDFuncsMutex sync.Mutex
	msgIDFuncs      map[string]messageIDFuncs

	hashFunc   hashFunc
	signFunc   signFunc
	verifyFunc verifyFunc

	mu    sync.Mutex
	dedup map[dedupKey][]byte // map[dedupKey]hash
}

func (s *server) getMessageIDFunc(msgID string) (messageIDFuncs, bool) {
	s.msgIDFuncsMutex.Lock()
	defer s.msgIDFuncsMutex.Unlock()

	fn, found := s.msgIDFuncs[msgID]

	return fn, found
}

func (s *server) registerMessageIDFuncs(msgID string, cb Callback, cm CheckMessage) {
	s.msgIDFuncsMutex.Lock()
	defer s.msgIDFuncsMutex.Unlock()

	s.msgIDFuncs[msgID] = messageIDFuncs{
		callback:     cb,
		checkMessage: cm,
	}
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

func (s *server) handleSigRequest(ctx context.Context, pID peer.ID, m proto.Message) (proto.Message, bool, error) {
	req, ok := m.(*pb.BCastSigRequest)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	fn, found := s.getMessageIDFunc(req.GetId())
	if !found {
		return nil, false, errors.New("unknown message id", z.Str("message_id", req.GetId()))
	}

	if err := fn.checkMessage(ctx, pID, req.GetMessage()); err != nil {
		return nil, false, errors.Wrap(err, "signature request message check")
	}

	reqMessageHash, err := s.hashFunc(req.GetMessage())
	if err != nil {
		return nil, false, errors.Wrap(err, "hash any")
	}

	// Only sign once per peer and message ID.
	if err := s.dedupHash(pID, req.GetId(), reqMessageHash); err != nil {
		return nil, false, errors.Wrap(err, "dedup")
	}

	sig, err := s.signFunc(req.GetId(), reqMessageHash)
	if err != nil {
		return nil, false, errors.Wrap(err, "sign hash")
	}

	return &pb.BCastSigResponse{Id: req.GetId(), Signature: sig}, true, nil
}

func (s *server) handleMessage(ctx context.Context, pID peer.ID, m proto.Message) (proto.Message, bool, error) {
	msg, ok := m.(*pb.BCastMessage)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	if err := s.verifyFunc(msg.GetId(), msg.GetMessage(), msg.GetSignatures()); err != nil {
		return nil, false, errors.Wrap(err, "verify signatures")
	}

	inner, err := msg.GetMessage().UnmarshalNew()
	if err != nil {
		return nil, false, errors.Wrap(err, "unmarshal any")
	}

	fn, found := s.getMessageIDFunc(msg.GetId())
	if !found {
		return nil, false, errors.New("unknown message id", z.Str("message_id", msg.GetId()))
	}

	if err := fn.callback(ctx, pID, msg.GetId(), inner); err != nil {
		return nil, false, errors.Wrap(err, "callback")
	}

	return nil, true, nil
}
