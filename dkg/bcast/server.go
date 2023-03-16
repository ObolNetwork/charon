// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// NewServer creates a new reliable-broadcast server.
func NewServer(tcpNode host.Host, singFunc SignFunc, verifyFunc VerifyFunc, callback Callback) *Server {
	s := &Server{
		callback:   callback,
		singFunc:   singFunc,
		verifyFunc: verifyFunc,
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

// Server is a reliable-broadcast server.
type Server struct {
	callback   Callback
	singFunc   SignFunc
	verifyFunc VerifyFunc
}

func (s *Server) handleSigRequest(_ context.Context, _ peer.ID, m proto.Message) (proto.Message, bool, error) {
	req, ok := m.(*pb.BCastSigRequest)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	sig, err := s.singFunc(req.Hash)
	if err != nil {
		return nil, false, errors.Wrap(err, "sign hash")
	}

	return &pb.BCastSigResponse{Signature: sig}, true, nil
}

func (s *Server) handleMessage(ctx context.Context, _ peer.ID, m proto.Message) (proto.Message, bool, error) {
	msg, ok := m.(*pb.BCastMessage)
	if !ok {
		return nil, false, errors.New("invalid message type")
	}

	if err := s.verifyFunc(msg.Message, msg.Signatures); err != nil {
		return nil, false, errors.Wrap(err, "verify signatures")
	}

	inner, err := msg.Message.UnmarshalNew()
	if err != nil {
		return nil, false, errors.Wrap(err, "unmarshal any")
	}

	if err := s.callback(ctx, inner); err != nil {
		return nil, false, errors.Wrap(err, "callback")
	}

	return nil, true, nil
}
