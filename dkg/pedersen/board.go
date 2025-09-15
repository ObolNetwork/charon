// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"bytes"
	"context"
	"path"

	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/dkg/bcast"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// Board implements kdkg.Board used to exchange protocol messages.
// Also, it implements logic for exchanging public keys before and after the DKG.
type Board struct {
	logCtx            context.Context
	host              host.Host
	config            *Config
	bcastComp         *bcast.Component
	dealCh            chan kdkg.DealBundle
	responseCh        chan kdkg.ResponseBundle
	justificationCh   chan kdkg.JustificationBundle
	nodePubKeysCh     chan PeerPubKey
	valPubKeySharesCh chan PeerPubKey
}

// PeerPubKey associates a peer ID with a certain public key.
type PeerPubKey struct {
	PeerID peer.ID
	PubKey []byte
}

const (
	protocolID = "/charon/dkg/pedersen/1.0.0"
)

var (
	_                 kdkg.Board = (*Board)(nil)
	nodePubKeyMsg                = path.Join(protocolID, "node_pubkey")
	valPubKeyShareMsg            = path.Join(protocolID, "val_pubkey_share")
	dealBundleMsg                = path.Join(protocolID, "deal_bundle")
	respBundleMsg                = path.Join(protocolID, "resp_bundle")
	justBundleMsg                = path.Join(protocolID, "just_bundle")
)

func NewBoard(ctx context.Context, host host.Host, config *Config, bcastComp *bcast.Component) *Board {
	board := &Board{
		logCtx:            log.WithTopic(ctx, "pedersen"),
		host:              host,
		config:            config,
		bcastComp:         bcastComp,
		dealCh:            make(chan kdkg.DealBundle),
		responseCh:        make(chan kdkg.ResponseBundle),
		justificationCh:   make(chan kdkg.JustificationBundle),
		nodePubKeysCh:     make(chan PeerPubKey, config.Nodes()),
		valPubKeySharesCh: make(chan PeerPubKey, config.Nodes()),
	}

	// We use bcast for exchanging node public keys only as they are invariant and sent only once.
	// This will leverage reliable broadcast and deduplication.
	bcastComp.RegisterMessageIDFuncs(nodePubKeyMsg, board.handleNodePubKeyMessage, checkPubKeyMessage)

	// For other messages we use direct p2p messaging.
	const logTopic = "pedersen"
	p2p.RegisterHandler(logTopic, host, protocol.ID(dealBundleMsg), func() proto.Message { return new(pb.PedersenDealBundle) }, board.handleDealBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(respBundleMsg), func() proto.Message { return new(pb.PedersenResponseBundle) }, board.handleResponseBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(justBundleMsg), func() proto.Message { return new(pb.PedersenJustificationBundle) }, board.handleJustificationBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(valPubKeyShareMsg), func() proto.Message { return new(pb.PubKeyMessage) }, board.handleValidatorPubKeyShareMessage)

	return board
}

// IncomingNodePubKeys returns a channel that will receive the node public keys as they are received.
func (b *Board) IncomingNodePubKeys() <-chan PeerPubKey {
	return b.nodePubKeysCh
}

// IncomingValidatorPubKeyShares returns a channel that will receive the validator public key shares as they are received.
func (b *Board) IncomingValidatorPubKeyShares() <-chan PeerPubKey {
	return b.valPubKeySharesCh
}

// IncomingDeal implements the kdkg.Board interface.
func (b *Board) IncomingDeal() <-chan kdkg.DealBundle {
	return b.dealCh
}

// IncomingResponse implements the kdkg.Board interface.
func (b *Board) IncomingResponse() <-chan kdkg.ResponseBundle {
	return b.responseCh
}

// IncomingJustification implements the kdkg.Board interface.
func (b *Board) IncomingJustification() <-chan kdkg.JustificationBundle {
	return b.justificationCh
}

// BroadcastNodePubKey broadcasts a public key and collects the public keys of all peers.
func (b *Board) BroadcastNodePubKey(ctx context.Context, pubKey []byte) error {
	msg := &pb.PubKeyMessage{
		SessionId: b.config.SessionID,
		PublicKey: pubKey,
	}
	if err := b.bcastComp.Broadcast(ctx, nodePubKeyMsg, msg); err != nil {
		return errors.Wrap(err, "broadcast node pubkey")
	}

	// bcastComp.Broadcast does not send to self, so we push our own key here.
	b.nodePubKeysCh <- PeerPubKey{
		PeerID: b.config.ThisPeerID,
		PubKey: pubKey,
	}

	return nil
}

// BroadcastValidatorPubKeyShare broadcasts a public key and collects the public keys of all peers.
func (b *Board) BroadcastValidatorPubKeyShare(ctx context.Context, share []byte) error {
	msg := &pb.PubKeyMessage{
		SessionId: b.config.SessionID,
		PublicKey: share,
	}

	for peerID := range b.config.PeerMap {
		if peerID == b.config.ThisPeerID {
			continue
		}

		if err := p2p.Send(ctx, b.host, protocol.ID(valPubKeyShareMsg), peerID, msg); err != nil {
			return errors.Wrap(err, "send validator pubkey share", z.Str("to", peerID.String()))
		}
	}

	b.valPubKeySharesCh <- PeerPubKey{
		PeerID: b.config.ThisPeerID,
		PubKey: share,
	}

	return nil
}

// PushDeals implements the kdkg.Board interface.
func (b *Board) PushDeals(bundle *kdkg.DealBundle) {
	msg, err := DealBundleToProto(*bundle)
	if err != nil {
		log.Error(b.logCtx, "Failed to create envelope from deal bundle", err)
		return
	}

	for peerID := range b.config.PeerMap {
		if peerID == b.config.ThisPeerID {
			continue
		}

		if err := p2p.Send(b.logCtx, b.host, protocol.ID(dealBundleMsg), peerID, msg); err != nil {
			log.Error(b.logCtx, "Failed to send deal bundle", err, z.Str("to", peerID.String()))
		}
	}
}

// PushResponses implements the kdkg.Board interface.
func (b *Board) PushResponses(bundle *kdkg.ResponseBundle) {
	msg, err := ResponseBundleToProto(*bundle)
	if err != nil {
		log.Error(b.logCtx, "Failed to create envelope from response bundle", err)
		return
	}

	for peerID := range b.config.PeerMap {
		if peerID == b.config.ThisPeerID {
			continue
		}

		if err := p2p.Send(b.logCtx, b.host, protocol.ID(respBundleMsg), peerID, msg); err != nil {
			log.Error(b.logCtx, "Failed to send response bundle", err, z.Str("to", peerID.String()))
		}
	}
}

// PushJustifications implements the kdkg.Board interface.
func (b *Board) PushJustifications(bundle *kdkg.JustificationBundle) {
	msg, err := JustificationBundleToProto(*bundle)
	if err != nil {
		log.Error(b.logCtx, "Failed to create envelope from justification bundle", err)
		return
	}

	for peerID := range b.config.PeerMap {
		if peerID == b.config.ThisPeerID {
			continue
		}

		if err := p2p.Send(b.logCtx, b.host, protocol.ID(justBundleMsg), peerID, msg); err != nil {
			log.Error(b.logCtx, "Failed to send justification bundle", err, z.Str("to", peerID.String()))
		}
	}
}

func (b *Board) handleNodePubKeyMessage(ctx context.Context, peerID peer.ID, _ string, msg proto.Message) error {
	protoMsg, ok := msg.(*pb.PubKeyMessage)
	if !ok {
		return errors.New("pubkey request malformed", z.Str("peer_id", peerID.String()))
	}

	if !bytes.Equal(protoMsg.GetSessionId(), b.config.SessionID) {
		return errors.New("validator pubkey share request session ID mismatch", z.Str("peer_id", peerID.String()))
	}

	select {
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping node pubkey, context done", nil, z.Str("from", peerID.String()))
	default:
	case b.nodePubKeysCh <- PeerPubKey{
		PeerID: peerID,
		PubKey: protoMsg.GetPublicKey(),
	}:
	}

	return nil
}

func (b *Board) handleValidatorPubKeyShareMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoMsg, ok := msg.(*pb.PubKeyMessage)
	if !ok {
		return nil, false, errors.New("validator pubkey share request malformed", z.Str("peer_id", peerID.String()))
	}

	if !bytes.Equal(protoMsg.GetSessionId(), b.config.SessionID) {
		return nil, false, errors.New("validator pubkey share request session ID mismatch", z.Str("peer_id", peerID.String()))
	}

	ppk := PeerPubKey{
		PeerID: peerID,
		PubKey: protoMsg.GetPublicKey(),
	}

	select {
	case b.valPubKeySharesCh <- ppk:
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping validator pubkey share, context done", nil, z.Str("from", peerID.String()))
	}

	return nil, true, nil
}

func (b *Board) handleDealBundleMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoBundle, ok := msg.(*pb.PedersenDealBundle)
	if !ok {
		return nil, false, errors.New("deal bundle request malformed", z.Str("peer_id", peerID.String()))
	}

	bundle, err := DealBundleFromProto(protoBundle, b.config.Suite)
	if err != nil {
		return nil, false, errors.Wrap(err, "deal bundle request invalid", z.Str("peer_id", peerID.String()))
	}

	select {
	case b.dealCh <- bundle:
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping deal bundle, context done", nil, z.Str("from", peerID.String()))
	}

	return nil, true, nil
}

func (b *Board) handleResponseBundleMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoBundle, ok := msg.(*pb.PedersenResponseBundle)
	if !ok {
		return nil, false, errors.New("response bundle request malformed", z.Str("peer_id", peerID.String()))
	}

	bundle, err := ResponseBundleFromProto(protoBundle)
	if err != nil {
		return nil, false, errors.Wrap(err, "response bundle request invalid", z.Str("peer_id", peerID.String()))
	}

	select {
	case b.responseCh <- bundle:
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping response bundle, context done", nil, z.Str("from", peerID.String()))
	}

	return nil, true, nil
}

func (b *Board) handleJustificationBundleMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoBundle, ok := msg.(*pb.PedersenJustificationBundle)
	if !ok {
		return nil, false, errors.New("justification bundle request malformed", z.Str("peer_id", peerID.String()))
	}

	bundle, err := JustificationBundleFromProto(protoBundle, b.config.Suite)
	if err != nil {
		return nil, false, errors.Wrap(err, "justification bundle request invalid", z.Str("peer_id", peerID.String()))
	}

	select {
	case b.justificationCh <- bundle:
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping justification bundle, context done", nil, z.Str("from", peerID.String()))
	}

	return nil, true, nil
}

func checkPubKeyMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg pb.PubKeyMessage

	if err := msgAny.UnmarshalTo(&msg); err != nil {
		return errors.Wrap(err, "pubkey request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}
