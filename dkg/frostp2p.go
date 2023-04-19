// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"path"
	"sync"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

var (
	round1CastID = string(frostProtocol("round1/cast"))
	round1P2PID  = frostProtocol("round1/p2p")
	round2CastID = string(frostProtocol("round2/cast"))
)

// newFrostP2P returns a p2p frost transport implementation.
func newFrostP2P(tcpNode host.Host, peers map[peer.ID]cluster.NodeIdx, secret *k1.PrivateKey, threshold, numVals int) *frostP2P {
	var (
		round1CastsRecv = make(chan *pb.FrostRound1Casts, len(peers))
		round1P2PRecv   = make(chan *pb.FrostRound1P2P, len(peers))
		round2CastsRecv = make(chan *pb.FrostRound2Casts, len(peers))
	)

	peerSlice := make([]peer.ID, len(peers))
	peersByShareIdx := make(map[uint32]peer.ID)
	for pID, nodeIdx := range peers {
		peerSlice[nodeIdx.PeerIdx] = pID
		peersByShareIdx[uint32(nodeIdx.ShareIdx)] = pID
	}

	// Register reliable broadcast protocol handlers.
	bcastFunc := bcast.New(tcpNode, peerSlice, secret, []string{round1CastID, round2CastID},
		bcastCallback(peers, round1CastsRecv, round2CastsRecv, threshold, numVals))

	// Register round 1 p2p protocol handlers.
	p2p.RegisterHandler("frost", tcpNode, round1P2PID,
		func() proto.Message { return new(pb.FrostRound1P2P) },
		p2pCallback(tcpNode, peers, round1P2PRecv, numVals),
		p2p.WithDelimitedProtocol(round1P2PID),
	)

	return &frostP2P{
		tcpNode:         tcpNode,
		peers:           peersByShareIdx,
		bcastFunc:       bcastFunc,
		round1CastsRecv: round1CastsRecv,
		round1P2PRecv:   round1P2PRecv,
		round2CastsRecv: round2CastsRecv,
	}
}

// bcastCallback returns a callback for broadcast in round 1 and round 2 of frost protocol.
func bcastCallback(peers map[peer.ID]cluster.NodeIdx, round1CastsRecv chan *pb.FrostRound1Casts, round2CastsRecv chan *pb.FrostRound2Casts, threshold, numVals int) bcast.Callback {
	var (
		mu               sync.Mutex
		dedupRound1Casts = make(map[peer.ID]bool)
		dedupRound2Casts = make(map[peer.ID]bool)
	)

	return func(ctx context.Context, pID peer.ID, msgID string, m proto.Message) error {
		switch msgID {
		case round1CastID:
			mu.Lock()
			defer mu.Unlock()

			if _, ok := dedupRound1Casts[pID]; ok {
				log.Debug(ctx, "Ignoring duplicate round 1 message", z.Any("peer", p2p.PeerName(pID)))
				return nil
			}
			dedupRound1Casts[pID] = true

			msg, ok := m.(*pb.FrostRound1Casts)
			if !ok {
				return errors.New("invalid round 1 casts message")
			}

			for _, cast := range msg.Casts {
				if int(cast.Key.SourceId) != peers[pID].ShareIdx {
					return errors.New("invalid round 1 cast source ID")
				} else if cast.Key.TargetId != 0 {
					return errors.New("invalid round 1 cast target ID")
				} else if int(cast.Key.ValIdx) < 0 || int(cast.Key.ValIdx) >= numVals {
					return errors.New("invalid round 1 cast validator index")
				}

				if len(cast.Commitments) != threshold {
					return errors.New("invalid amount of commitments in round 1",
						z.Int("received", len(cast.Commitments)),
						z.Int("expected", threshold),
					)
				}
			}

			round1CastsRecv <- msg
		case round2CastID:
			mu.Lock()
			defer mu.Unlock()

			if _, ok := dedupRound2Casts[pID]; ok {
				log.Debug(ctx, "Ignoring duplicate round 2 message", z.Any("peer", p2p.PeerName(pID)))
				return nil
			}
			dedupRound2Casts[pID] = true

			msg, ok := m.(*pb.FrostRound2Casts)
			if !ok {
				return errors.New("invalid round 2 casts message")
			}

			for _, cast := range msg.Casts {
				if int(cast.Key.SourceId) != peers[pID].ShareIdx {
					return errors.New("invalid round 2 cast source ID")
				} else if cast.Key.TargetId != 0 {
					return errors.New("invalid round 2 cast target ID")
				} else if int(cast.Key.ValIdx) < 0 || int(cast.Key.ValIdx) >= numVals {
					return errors.New("invalid round 2 cast validator index")
				}
			}

			round2CastsRecv <- msg
		default:
			return errors.New("bug: unexpected invalid message ID")
		}

		return nil
	}
}

// p2pCallback returns a callback for P2P messages in round 1 of frost protocol.
func p2pCallback(tcpNode host.Host, peers map[peer.ID]cluster.NodeIdx, round1P2PRecv chan *pb.FrostRound1P2P, numVals int) p2p.HandlerFunc {
	var (
		mu             sync.Mutex
		dedupRound1P2P = make(map[peer.ID]bool)
	)

	return func(ctx context.Context, pID peer.ID, req proto.Message) (proto.Message, bool, error) {
		mu.Lock()
		defer mu.Unlock()

		msg, ok := req.(*pb.FrostRound1P2P)
		if !ok {
			return nil, false, errors.New("invalid round 1 p2p message")
		}

		for _, share := range msg.Shares {
			if int(share.Key.SourceId) != peers[pID].ShareIdx {
				return nil, false, errors.New("invalid round 1 p2p source ID")
			} else if int(share.Key.TargetId) != peers[tcpNode.ID()].ShareIdx {
				return nil, false, errors.New("invalid round 1 p2p target ID")
			} else if int(share.Key.ValIdx) < 0 || int(share.Key.ValIdx) >= numVals {
				return nil, false, errors.New("invalid round 1 p2p validator index")
			}
		}

		if dedupRound1P2P[pID] {
			log.Debug(ctx, "Ignoring duplicate round 2 message", z.Any("peer", p2p.PeerName(pID)))
			return nil, false, nil
		}
		dedupRound1P2P[pID] = true

		round1P2PRecv <- msg

		return nil, false, nil
	}
}

// frostP2P implements frost transport.
type frostP2P struct {
	tcpNode         host.Host
	peers           map[uint32]peer.ID // map[shareIdx)peerID
	bcastFunc       bcast.BroadcastFunc
	round1CastsRecv chan *pb.FrostRound1Casts
	round1P2PRecv   chan *pb.FrostRound1P2P
	round2CastsRecv chan *pb.FrostRound2Casts
}

// Round1 returns results of all round 1 communication; the received round 1 broadcasts from all other nodes
// and the round 1 P2P sends to this node.
func (f *frostP2P) Round1(ctx context.Context, castR1 map[msgKey]frost.Round1Bcast, p2pR1 map[msgKey]sharing.ShamirShare,
) (map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error) {
	// Build broadcast message
	casts := new(pb.FrostRound1Casts)
	for key, cast := range castR1 {
		cast := round1CastToProto(key, cast)
		casts.Casts = append(casts.Casts, cast)
	}
	// Broadcast reliably to others
	err := f.bcastFunc(ctx, round1CastID, casts)
	if err != nil {
		return nil, nil, err
	}
	f.round1CastsRecv <- casts // Send to self

	// Build P2P messages to send directly to peers.
	p2pMsgs := make(map[peer.ID]*pb.FrostRound1P2P)
	for key, share := range p2pR1 {
		pID, ok := f.peers[key.TargetID]
		if !ok {
			return nil, nil, errors.New("unknown target")
		}

		p2pMsg, ok := p2pMsgs[pID]
		if !ok {
			p2pMsg = new(pb.FrostRound1P2P)
		}
		p2pMsg.Shares = append(p2pMsg.Shares, shamirShareToProto(key, share))
		p2pMsgs[pID] = p2pMsg
	}

	// Send messages to all peers
	for pID, p2pMsg := range p2pMsgs {
		if pID == f.tcpNode.ID() {
			return nil, nil, errors.New("bug: unexpected p2p message to self")
		}

		err := p2p.Send(ctx, f.tcpNode, round1P2PID, pID, p2pMsg, p2p.WithDelimitedProtocol(round1P2PID))
		if err != nil {
			return nil, nil, err
		}
	}

	// Wait for all incoming messages
	var (
		castsRecvs []*pb.FrostRound1Casts
		p2pRecvs   []*pb.FrostRound1P2P
	)
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case msg := <-f.round1CastsRecv:
			castsRecvs = append(castsRecvs, msg)
			if len(castsRecvs) > len(f.peers) {
				return nil, nil, errors.New("too many round 1 casts messages")
			}
		case msg := <-f.round1P2PRecv:
			p2pRecvs = append(p2pRecvs, msg)
			if len(p2pRecvs) > len(f.peers)-1 {
				return nil, nil, errors.New("too many round 1 p2p messages")
			}
		}

		if len(castsRecvs) == len(f.peers) && len(p2pRecvs) == len(f.peers)-1 {
			break
		}
	}

	return makeRound1Response(castsRecvs, p2pRecvs)
}

// Round2 returns results of all round 2 communication; the received round 2 broadcasts from all other nodes.
func (f *frostP2P) Round2(ctx context.Context, castR2 map[msgKey]frost.Round2Bcast) (map[msgKey]frost.Round2Bcast, error) {
	// Build broadcast message
	casts := new(pb.FrostRound2Casts)
	for key, cast := range castR2 {
		cast := round2CastToProto(key, cast)
		casts.Casts = append(casts.Casts, cast)
	}
	// Broadcast reliably
	err := f.bcastFunc(ctx, round2CastID, casts)
	if err != nil {
		return nil, err
	}
	f.round2CastsRecv <- casts // Send to self

	// Wait for all incoming messages
	var castsRecvs []*pb.FrostRound2Casts
	for len(castsRecvs) != len(f.peers) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg := <-f.round2CastsRecv:
			castsRecvs = append(castsRecvs, msg)
		}
	}

	return makeRound2Response(castsRecvs)
}

// makeRound1Response returns the round 1 response from the list of received messages.
func makeRound1Response(casts []*pb.FrostRound1Casts, p2ps []*pb.FrostRound1P2P) (map[msgKey]frost.Round1Bcast, map[msgKey]sharing.ShamirShare, error) {
	var (
		castMap = make(map[msgKey]frost.Round1Bcast)
		p2pMap  = make(map[msgKey]sharing.ShamirShare)
	)
	for _, msg := range casts {
		for _, castPB := range msg.Casts {
			key, cast, err := round1CastFromProto(castPB)
			if err != nil {
				return nil, nil, err
			}

			castMap[key] = cast
		}
	}

	for _, msg := range p2ps {
		for _, sharePB := range msg.Shares {
			key, share, err := shamirShareFromProto(sharePB)
			if err != nil {
				return nil, nil, err
			}

			p2pMap[key] = share
		}
	}

	return castMap, p2pMap, nil
}

// makeRound2Response returns the round 2 response from the list of received messages.
func makeRound2Response(msgs []*pb.FrostRound2Casts) (map[msgKey]frost.Round2Bcast, error) {
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

func shamirShareToProto(key msgKey, shamir sharing.ShamirShare) *pb.FrostRound1ShamirShare {
	return &pb.FrostRound1ShamirShare{
		Key:   keyToProto(key),
		Id:    shamir.Id,
		Value: shamir.Value,
	}
}

func shamirShareFromProto(shamir *pb.FrostRound1ShamirShare) (msgKey, sharing.ShamirShare, error) {
	if shamir == nil {
		return msgKey{}, sharing.ShamirShare{}, errors.New("round 1 shamir share proto cannot be nil")
	}

	protoKey, err := keyFromProto(shamir.Key)
	if err != nil {
		return msgKey{}, sharing.ShamirShare{}, err
	}

	return protoKey, sharing.ShamirShare{
		Id:    shamir.Id,
		Value: shamir.Value,
	}, nil
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
	if cast == nil {
		return msgKey{}, frost.Round1Bcast{}, errors.New("round 1 cast cannot be nil")
	}

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

	key, err := keyFromProto(cast.Key)
	if err != nil {
		return msgKey{}, frost.Round1Bcast{}, err
	}

	return key, frost.Round1Bcast{
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
	if cast == nil {
		return msgKey{}, frost.Round2Bcast{}, errors.New("round 2 cast cannot be nil")
	}

	verificationKey, err := curve.Point.FromAffineCompressed(cast.VerificationKey)
	if err != nil {
		return msgKey{}, frost.Round2Bcast{}, errors.Wrap(err, "decode verification key scalar")
	}
	vkShare, err := curve.Point.FromAffineCompressed(cast.VkShare)
	if err != nil {
		return msgKey{}, frost.Round2Bcast{}, errors.Wrap(err, "decode c1 scalar")
	}

	key, err := keyFromProto(cast.Key)
	if err != nil {
		return msgKey{}, frost.Round2Bcast{}, err
	}

	return key, frost.Round2Bcast{
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

func keyFromProto(key *pb.FrostMsgKey) (msgKey, error) {
	if key == nil {
		return msgKey{}, errors.New("frost msg key cannot be nil")
	}

	return msgKey{
		ValIdx:   key.ValIdx,
		SourceID: key.SourceId,
		TargetID: key.TargetId,
	}, nil
}

// frostProtocol returns the frost protocol ID including the provided suffixes.
func frostProtocol(suffix string) protocol.ID {
	return protocol.ID(path.Join("/charon/dkg/frost/2.0.0/", suffix))
}
