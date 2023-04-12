// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

const (
	protocolID1 = "/charon/parsigex/1.0.0"
	protocolID2 = "/charon/parsigex/2.0.0"
)

// Protocols returns the supported protocols of this package in order of precedence.
func Protocols() []protocol.ID {
	return []protocol.ID{protocolID2, protocolID1}
}

func NewParSigEx(tcpNode host.Host, sendFunc p2p.SendFunc, peerIdx int, peers []peer.ID, verifyFunc func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error) *ParSigEx {
	parSigEx := &ParSigEx{
		tcpNode:    tcpNode,
		sendFunc:   sendFunc,
		peerIdx:    peerIdx,
		peers:      peers,
		verifyFunc: verifyFunc,
	}

	newReq := func() proto.Message { return new(pbv1.ParSigExMsg) }
	p2p.RegisterHandler("parsigex", tcpNode, protocolID1, newReq, parSigEx.handle, p2p.WithDelimitedProtocol(protocolID2))

	return parSigEx
}

// ParSigEx exchanges partially signed duty data sets.
// It ensures that all partial signatures are persisted by all peers.
type ParSigEx struct {
	tcpNode    host.Host
	sendFunc   p2p.SendFunc
	peerIdx    int
	peers      []peer.ID
	verifyFunc func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error
	subs       []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (m *ParSigEx) handle(ctx context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
	pb, ok := req.(*pbv1.ParSigExMsg)
	if !ok {
		return nil, false, errors.New("invalid request type")
	}

	duty := core.DutyFromProto(pb.Duty)
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	set, err := core.ParSignedDataSetFromProto(duty.Type, pb.DataSet)
	if err != nil {
		return nil, false, errors.Wrap(err, "convert parsigex proto")
	}

	ctx, span := core.StartDutyTrace(ctx, duty, "core/parsigex.Handle")
	defer span.End()

	// Verify partial signature
	for pubkey, data := range set {
		if err = m.verifyFunc(ctx, duty, pubkey, data); err != nil {
			return nil, false, errors.Wrap(err, "invalid partial signature")
		}
	}

	for _, sub := range m.subs {
		// TODO(corver): Call this async
		err := sub(ctx, duty, set)
		if err != nil {
			log.Error(ctx, "Subscribe error", err)
		}
	}

	return nil, false, nil
}

// Broadcast broadcasts the partially signed duty data set to all peers.
func (m *ParSigEx) Broadcast(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
	ctx = log.WithTopic(ctx, "parsigex")

	pb, err := core.ParSignedDataSetToProto(set)
	if err != nil {
		return err
	}

	msg := pbv1.ParSigExMsg{
		Duty:    core.DutyToProto(duty),
		DataSet: pb,
	}

	for i, p := range m.peers {
		// Don't send to self
		if i == m.peerIdx {
			continue
		}

		if err := m.sendFunc(ctx, m.tcpNode, protocolID1, p, &msg, p2p.WithDelimitedProtocol(protocolID2)); err != nil {
			return err
		}
	}

	return nil
}

// Subscribe registers a callback when a partially signed duty set
// is received from a peer. This is not thread safe, it must be called before starting to use parsigex.
func (m *ParSigEx) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	m.subs = append(m.subs, fn)
}

// NewEth2Verifier returns a partial signature verification function for core workflow eth2 signatures.
func NewEth2Verifier(eth2Cl eth2wrap.Client, pubSharesByKey map[core.PubKey]map[int]tbls.PublicKey) (func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error, error) {
	return func(ctx context.Context, duty core.Duty, pubkey core.PubKey, data core.ParSignedData) error {
		pubshares, ok := pubSharesByKey[pubkey]
		if !ok {
			return errors.New("unknown pubkey, not part of cluster lock")
		}

		pubshare, ok := pubshares[data.ShareIdx]
		if !ok {
			return errors.New("invalid shareIdx")
		}

		eth2Signed, ok := data.SignedData.(core.Eth2SignedData)
		if !ok {
			return errors.New("invalid eth2 signed data")
		}

		err := core.VerifyEth2SignedData(ctx, eth2Cl, eth2Signed, pubshare)
		if err != nil {
			return errors.Wrap(err, "invalid signature", z.Str("duty", duty.String()))
		}

		return nil
	}, nil
}
