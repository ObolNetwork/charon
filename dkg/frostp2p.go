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

package dkg

import (
	"context"
	"fmt"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// newFrostP2P returns a p2p front transport implementation.
func newFrostP2P(ctx context.Context, tcpNode host.Host, peers map[uint32]peer.ID, clusterID string) *frostP2P {
	var (
		round1Recv  = make(chan *pb.FrostRound1Msg, len(peers))
		round2Recv  = make(chan *pb.FrostRound2Msg, len(peers))
		dedupRound1 = make(map[peer.ID]bool)
		dedupRound2 = make(map[peer.ID]bool)
		knownPeers  = make(map[peer.ID]bool)
	)

	for _, id := range peers {
		knownPeers[id] = true
	}

	tcpNode.SetStreamHandler(round1Protocol(clusterID), func(s network.Stream) {
		defer s.Close()

		b, err := io.ReadAll(s)
		if err != nil {
			log.Error(ctx, "Read round 1 wire", err)
			return
		}
		msg := new(pb.FrostRound1Msg)
		if err := proto.Unmarshal(b, msg); err != nil {
			log.Error(ctx, "Unmarshal round 1 proto", err)
			return
		}

		pID := s.Conn().RemotePeer()
		if !knownPeers[pID] {
			log.Warn(ctx, "Ignoring unknown round 1 peer", nil, z.Any("peer", p2p.ShortID(pID)))
			return
		} else if dedupRound1[pID] {
			log.Debug(ctx, "Ignoring duplicate round 1 message", z.Any("peer", p2p.ShortID(pID)))
			return
		}
		dedupRound1[pID] = true

		round1Recv <- msg
	})

	tcpNode.SetStreamHandler(round2Protocol(clusterID), func(s network.Stream) {
		defer s.Close()

		b, err := io.ReadAll(s)
		if err != nil {
			log.Error(ctx, "Read round 2 wire", err)
			return
		}
		msg := new(pb.FrostRound2Msg)
		if err := proto.Unmarshal(b, msg); err != nil {
			log.Error(ctx, "Unmarshal round 2 proto", err)
			return
		}

		pID := s.Conn().RemotePeer()
		if !knownPeers[pID] {
			log.Warn(ctx, "Ignoring unknown round 2 peer", nil, z.Any("peer", p2p.ShortID(pID)))
			return
		} else if dedupRound2[pID] {
			log.Debug(ctx, "Ignoring duplicate round 2 message", z.Any("peer", p2p.ShortID(pID)))
			return
		}
		dedupRound2[pID] = true

		round2Recv <- msg
	})

	return &frostP2P{
		tcpNode:    tcpNode,
		peers:      peers,
		clusterID:  clusterID,
		round1Recv: round1Recv,
		round2Recv: round2Recv,
	}
}

// frostP2P implements frost transport.
type frostP2P struct {
	tcpNode    host.Host
	peers      map[uint32]peer.ID
	clusterID  string
	round1Recv chan *pb.FrostRound1Msg
	round2Recv chan *pb.FrostRound2Msg
}

func (f *frostP2P) Round1(ctx context.Context, castR1 map[msgKey]frost.Round1Bcast, p2pR1 map[msgKey]sharing.ShamirShare,
) (map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error) {
	// Build peer messages
	peerMsgs := make(map[peer.ID]*pb.FrostRound1Msg)

	// Append broadcast to all peers
	for key, cast := range castR1 {
		for targetID, pID := range f.peers {
			key := key
			key.TargetID = targetID
			msgpb := round1CastToProto(key, cast)

			msg, ok := peerMsgs[pID]
			if !ok {
				msg = new(pb.FrostRound1Msg)
			}
			msg.Casts = append(msg.Casts, msgpb)
			peerMsgs[pID] = msg
		}
	}

	// Append p2p to specific peers
	for key, share := range p2pR1 {
		msgpb := shamirShareToProto(key, share)
		pID, ok := f.peers[key.TargetID]
		if !ok {
			return nil, nil, errors.New("unknown target")
		}
		msg := peerMsgs[pID]
		msg.P2Ps = append(msg.P2Ps, msgpb)
		peerMsgs[pID] = msg
	}

	// Send messages to all peers
	for id, msg := range peerMsgs {
		if id == f.tcpNode.ID() {
			// Send to self
			f.round1Recv <- msg
			continue
		}
		err := f.send(ctx, id, round1Protocol(f.clusterID), msg)
		if err != nil {
			return nil, nil, err
		}
	}

	// Wait for all incoming messages
	var recvs []*pb.FrostRound1Msg
	for len(recvs) < len(f.peers) {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case msg := <-f.round1Recv:
			recvs = append(recvs, msg)
		}
	}

	return makeRound1Response(recvs)
}

func (f *frostP2P) Round2(ctx context.Context, castR2 map[msgKey]frost.Round2Bcast) (map[msgKey]frost.Round2Bcast, error) {
	// Build peer messages
	peerMsgs := make(map[peer.ID]*pb.FrostRound2Msg)

	// Append broadcast to all peers
	for key, cast := range castR2 {
		for targetID, pID := range f.peers {
			key := key
			key.TargetID = targetID
			msgpb := round2CastToProto(key, cast)

			msg, ok := peerMsgs[pID]
			if !ok {
				msg = new(pb.FrostRound2Msg)
			}
			msg.Casts = append(msg.Casts, msgpb)
			peerMsgs[pID] = msg
		}
	}

	// Send messages to all peers
	for id, msg := range peerMsgs {
		if id == f.tcpNode.ID() {
			// Send to self
			f.round2Recv <- msg
			continue
		}
		err := f.send(ctx, id, round2Protocol(f.clusterID), msg)
		if err != nil {
			return nil, err
		}
	}

	// Wait for all incoming messages
	var recvs []*pb.FrostRound2Msg
	for len(recvs) < len(f.peers) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg := <-f.round2Recv:
			recvs = append(recvs, msg)
		}
	}

	return makeRound2Response(recvs)
}

// send sends the proto msg to the peer using the protocol id.
func (f *frostP2P) send(ctx context.Context, p peer.ID, id protocol.ID, msg proto.Message) error {
	s, err := f.tcpNode.NewStream(ctx, p, id)
	if err != nil {
		return errors.Wrap(err, "new stream")
	}
	defer s.Close()

	b, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	if _, err = s.Write(b); err != nil {
		return errors.Wrap(err, "marshal proto")
	}

	return nil
}

// makeRound1Response returns the round 1 response from the list of received messages.
func makeRound1Response(msgs []*pb.FrostRound1Msg) (map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error) {
	var (
		castMap = make(map[msgKey]frost.Round1Bcast)
		p2pMap  = make(map[msgKey]sharing.ShamirShare)
	)
	for _, msg := range msgs {
		for _, castPB := range msg.Casts {
			key, cast, err := round1CastFromProto(castPB)
			if err != nil {
				return nil, nil, err
			}
			castMap[key] = cast
		}
		for _, sharePB := range msg.P2Ps {
			key, share := shamirShareFromProto(sharePB)
			p2pMap[key] = share
		}
	}

	return castMap, p2pMap, nil
}

// makeRound2Response returns the round 2 response from the list of received messages.
func makeRound2Response(msgs []*pb.FrostRound2Msg) (map[msgKey]frost.Round2Bcast, error) {
	castMap := make(map[msgKey]frost.Round2Bcast)
	for _, msg := range msgs {
		for _, castPB := range msg.Casts {
			key, cast, err := round2CastFromProto(castPB)
			if err != nil {
				return nil, err
			}
			castMap[key] = cast
		}
	}

	return castMap, nil
}

func shamirShareToProto(key msgKey, shamir sharing.ShamirShare) *pb.ShamirShare {
	return &pb.ShamirShare{
		Key:   keyToProto(key),
		Id:    shamir.Id,
		Value: shamir.Value,
	}
}

func shamirShareFromProto(shamir *pb.ShamirShare) (msgKey, sharing.ShamirShare) {
	return keyFromProto(shamir.Key), sharing.ShamirShare{
		Id:    shamir.Id,
		Value: shamir.Value,
	}
}

func round1CastToProto(key msgKey, cast frost.Round1Bcast) *pb.FrostRound1Cast {
	var commBytes [][]byte
	for _, comm := range cast.Verifiers.Commitments {
		commBytes = append(commBytes, comm.ToAffineCompressed())
	}

	return &pb.FrostRound1Cast{
		Key:         keyToProto(key),
		Wi:          cast.Wi.Bytes(),
		Ci:          cast.Ci.Bytes(),
		Commitments: commBytes,
	}
}

func round1CastFromProto(cast *pb.FrostRound1Cast) (msgKey, frost.Round1Bcast, error) {
	wi, err := curve.Scalar.SetBytes(cast.Wi)
	if err != nil {
		return msgKey{}, frost.Round1Bcast{}, errors.Wrap(err, "decode wi scalar")
	}
	ci, err := curve.Scalar.SetBytes(cast.Ci)
	if err != nil {
		return msgKey{}, frost.Round1Bcast{}, errors.Wrap(err, "decode c1 scalar")
	}

	var comms []curves.Point
	for _, comm := range cast.Commitments {
		c, err := curve.Point.FromAffineCompressed(comm)
		if err != nil {
			return msgKey{}, frost.Round1Bcast{}, errors.Wrap(err, "decode commitment")
		}

		comms = append(comms, c)
	}

	return keyFromProto(cast.Key), frost.Round1Bcast{
		Wi:        wi,
		Ci:        ci,
		Verifiers: &sharing.FeldmanVerifier{Commitments: comms},
	}, nil
}

func round2CastToProto(key msgKey, cast frost.Round2Bcast) *pb.FrostRound2Cast {
	return &pb.FrostRound2Cast{
		Key:             keyToProto(key),
		VerificationKey: cast.VerificationKey.ToAffineCompressed(),
		VkShare:         cast.VkShare.ToAffineCompressed(),
	}
}

func round2CastFromProto(cast *pb.FrostRound2Cast) (msgKey, frost.Round2Bcast, error) {
	verificationKey, err := curve.Point.FromAffineCompressed(cast.VerificationKey)
	if err != nil {
		return msgKey{}, frost.Round2Bcast{}, errors.Wrap(err, "decode verification key scalar")
	}
	vkShare, err := curve.Point.FromAffineCompressed(cast.VkShare)
	if err != nil {
		return msgKey{}, frost.Round2Bcast{}, errors.Wrap(err, "decode c1 scalar")
	}

	return keyFromProto(cast.Key), frost.Round2Bcast{
		VerificationKey: verificationKey,
		VkShare:         vkShare,
	}, nil
}

func keyToProto(key msgKey) *pb.FrostMsgKey {
	return &pb.FrostMsgKey{
		ValIdx:   key.ValIdx,
		SourceId: key.SourceID,
		TargetId: key.TargetID,
	}
}

func keyFromProto(key *pb.FrostMsgKey) msgKey {
	return msgKey{
		ValIdx:   key.ValIdx,
		SourceID: key.SourceId,
		TargetID: key.TargetId,
	}
}

// round1Protocol returns the frost round 1 protocol ID including the cluster ID.
func round1Protocol(clusterID string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/charon/dkg/frost/round1/1.0.0/%s", clusterID))
}

// round2Protocol returns the frost round 2 protocol ID including the cluster ID.
func round2Protocol(clusterID string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/charon/dkg/frost/round2/1.0.0/%s", clusterID))
}
