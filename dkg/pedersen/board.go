// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path"
	"sync"
	"time"

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
	logCtx             context.Context
	host               host.Host
	sender             *p2p.Sender
	config             *Config
	bcastComp          *bcast.Component
	dedup              *bundleDedup
	dealCh             chan kdkg.DealBundle
	responseCh         chan kdkg.ResponseBundle
	justificationCh    chan kdkg.JustificationBundle
	dealOutCh          chan kdkg.DealBundle
	responseOutCh      chan kdkg.ResponseBundle
	justificationOutCh chan kdkg.JustificationBundle
	nodePubKeysCh      chan NodePubKeys
	valPubKeySharesCh  chan ValidatorPubKeyShare
}

type NodePubKeys struct {
	PeerID       peer.ID
	PubKey       []byte
	PubKeyShares [][]byte
}

type ValidatorPubKeyShare struct {
	PeerID          peer.ID
	ValidatorPubKey []byte
}

const (
	protocolID = "/charon/dkg/pedersen/1.0.0"

	// sendRetries is the number of additional p2p send attempts. A DKG ceremony cannot
	// complete if a bundle is dropped, so transient failures (e.g. a stalled relay
	// connection) are retried instead. Receivers deduplicate re-delivered messages.
	sendRetries = 2

	// sendTimeout is the p2p send deadline per attempt. Ceremony peers may lag behind
	// (e.g. slower operators or relay-routed connections), so sends get much more
	// headroom than the 7s p2p default.
	sendTimeout = time.Minute
)

var (
	_                 kdkg.Board = (*Board)(nil)
	nodePubKeysMsg               = path.Join(protocolID, "node_pubkeys")
	valPubKeyShareMsg            = path.Join(protocolID, "val_pubkey_share")
	dealBundleMsg                = path.Join(protocolID, "deal_bundle")
	respBundleMsg                = path.Join(protocolID, "resp_bundle")
	justBundleMsg                = path.Join(protocolID, "just_bundle")
)

// NewBoard creates a new Board instance.
// Kyber implementation does not pass context to the Board methods, so we have to inject one here.
// In the future Kyber fork we will address this and fix all logging as well.
func NewBoard(ctx context.Context, host host.Host, config *Config, bcastComp *bcast.Component) *Board {
	board := &Board{
		logCtx:             log.WithTopic(ctx, "pedersen"),
		host:               host,
		sender:             new(p2p.Sender),
		config:             config,
		bcastComp:          bcastComp,
		dedup:              newBundleDedup(),
		dealCh:             make(chan kdkg.DealBundle),
		responseCh:         make(chan kdkg.ResponseBundle),
		justificationCh:    make(chan kdkg.JustificationBundle),
		dealOutCh:          make(chan kdkg.DealBundle),
		responseOutCh:      make(chan kdkg.ResponseBundle),
		justificationOutCh: make(chan kdkg.JustificationBundle),
		nodePubKeysCh:      make(chan NodePubKeys, config.Nodes()),
		valPubKeySharesCh:  make(chan ValidatorPubKeyShare, config.Nodes()),
	}

	// Bundles reach kyber via forwarders that close their output channels when the
	// protocol context is done. Kyber FastSync protocol goroutines exit when a board
	// channel closes, so an aborted ceremony does not leak running DKG goroutines.
	go forwardBundles(ctx, board.dealCh, board.dealOutCh)
	go forwardBundles(ctx, board.responseCh, board.responseOutCh)
	go forwardBundles(ctx, board.justificationCh, board.justificationOutCh)

	// We use bcast for exchanging node public keys only as they are invariant and sent only once.
	// This will leverage reliable broadcast and deduplication.
	bcastComp.RegisterMessageIDFuncs(nodePubKeysMsg, board.handleNodePubKeyMessage, checkNodePubKeyMessage)

	// For other messages we use direct p2p messaging.
	const logTopic = "pedersen"
	p2p.RegisterHandler(logTopic, host, protocol.ID(dealBundleMsg), func() proto.Message { return new(pb.PedersenDealBundle) }, board.handleDealBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(respBundleMsg), func() proto.Message { return new(pb.PedersenResponseBundle) }, board.handleResponseBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(justBundleMsg), func() proto.Message { return new(pb.PedersenJustificationBundle) }, board.handleJustificationBundleMessage)
	p2p.RegisterHandler(logTopic, host, protocol.ID(valPubKeyShareMsg), func() proto.Message { return new(pb.ValidatorPubKeyShareMessage) }, board.handleValidatorPubKeyShareMessage)

	return board
}

// IncomingNodePubKeys returns a channel that will receive the node public keys as they are received.
func (b *Board) IncomingNodePubKeys() <-chan NodePubKeys {
	return b.nodePubKeysCh
}

// IncomingValidatorPubKeyShares returns a channel that will receive the validator public key shares as they are received.
func (b *Board) IncomingValidatorPubKeyShares() <-chan ValidatorPubKeyShare {
	return b.valPubKeySharesCh
}

// IncomingDeal implements the kdkg.Board interface.
func (b *Board) IncomingDeal() <-chan kdkg.DealBundle {
	return b.dealOutCh
}

// IncomingResponse implements the kdkg.Board interface.
func (b *Board) IncomingResponse() <-chan kdkg.ResponseBundle {
	return b.responseOutCh
}

// IncomingJustification implements the kdkg.Board interface.
func (b *Board) IncomingJustification() <-chan kdkg.JustificationBundle {
	return b.justificationOutCh
}

// BroadcastNodePubKey broadcasts a public key and collects the public keys of all peers.
func (b *Board) BroadcastNodePubKey(ctx context.Context, pubKey []byte) error {
	return b.BroadcastNodePubKeyWithShares(ctx, pubKey, nil)
}

func (b *Board) BroadcastNodePubKeyWithShares(ctx context.Context, pubKey []byte, pubKeyShares [][]byte) error {
	var shares *pb.NodePubKeyShares
	if len(pubKeyShares) > 0 {
		shares = &pb.NodePubKeyShares{
			PublicKeyShares: pubKeyShares,
		}
	}

	msg := &pb.NodePubKeyMessage{
		SessionId: b.config.SessionID,
		PublicKey: pubKey,
		Shares:    shares,
	}

	if err := b.bcastComp.Broadcast(ctx, nodePubKeysMsg, msg); err != nil {
		return errors.Wrap(err, "broadcast node pubkeys")
	}

	// bcastComp.Broadcast does not send to self, so we push our own key here.
	b.nodePubKeysCh <- NodePubKeys{
		PeerID:       b.config.ThisPeerID,
		PubKey:       pubKey,
		PubKeyShares: pubKeyShares,
	}

	return nil
}

// BroadcastValidatorPubKeyShare broadcasts a public key and collects the public keys of all peers.
func (b *Board) BroadcastValidatorPubKeyShare(ctx context.Context, share []byte) error {
	msg := &pb.ValidatorPubKeyShareMessage{
		SessionId:      b.config.SessionID,
		PublicKeyShare: share,
	}

	if err := b.broadcastP2P(ctx, valPubKeyShareMsg, msg); err != nil {
		log.Error(b.logCtx, "Failed to broadcast val pubkey share", err)
	}

	b.valPubKeySharesCh <- ValidatorPubKeyShare{
		PeerID:          b.config.ThisPeerID,
		ValidatorPubKey: share,
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

	if err := b.broadcastP2P(b.logCtx, dealBundleMsg, msg); err != nil {
		log.Error(b.logCtx, "Failed to broadcast deal bundle", err)
	}

	go func() {
		select {
		case b.dealCh <- *bundle:
		case <-b.logCtx.Done(): // Do not leak the self-send once the protocol is aborted.
		}
	}()
}

// PushResponses implements the kdkg.Board interface.
func (b *Board) PushResponses(bundle *kdkg.ResponseBundle) {
	logComplaints(b.logCtx, "Sending DKG complaints, deals from these dealers failed verification", b.config.ThisPeerID, *bundle)

	msg, err := ResponseBundleToProto(*bundle)
	if err != nil {
		log.Error(b.logCtx, "Failed to create envelope from response bundle", err)
		return
	}

	if err := b.broadcastP2P(b.logCtx, respBundleMsg, msg); err != nil {
		log.Error(b.logCtx, "Failed to broadcast response bundle", err)
	}

	go func() {
		select {
		case b.responseCh <- *bundle:
		case <-b.logCtx.Done(): // Do not leak the self-send once the protocol is aborted.
		}
	}()
}

// PushJustifications implements the kdkg.Board interface.
func (b *Board) PushJustifications(bundle *kdkg.JustificationBundle) {
	msg, err := JustificationBundleToProto(*bundle)
	if err != nil {
		log.Error(b.logCtx, "Failed to create envelope from justification bundle", err)
		return
	}

	if err := b.broadcastP2P(b.logCtx, justBundleMsg, msg); err != nil {
		log.Error(b.logCtx, "Failed to broadcast justification bundle", err)
	}

	go func() {
		select {
		case b.justificationCh <- *bundle:
		case <-b.logCtx.Done(): // Do not leak the self-send once the protocol is aborted.
		}
	}()
}

func (b *Board) broadcastP2P(ctx context.Context, msgID string, msg proto.Message) error {
	for peerID := range b.config.PeerMap {
		if peerID == b.config.ThisPeerID {
			continue
		}

		if err := b.sender.SendAsync(ctx, b.host, protocol.ID(msgID), peerID, msg, p2p.WithSendTimeout(sendTimeout), p2p.WithRetries(sendRetries)); err != nil {
			return errors.Wrap(err, "p2p send", z.Str("msg", msgID), z.Str("to", peerID.String()))
		}
	}

	return nil
}

func (b *Board) handleNodePubKeyMessage(ctx context.Context, peerID peer.ID, _ string, msg proto.Message) error {
	protoMsg, ok := msg.(*pb.NodePubKeyMessage)
	if !ok {
		return errors.New("pubkey request malformed", z.Str("peer_id", peerID.String()))
	}

	if !bytes.Equal(protoMsg.GetSessionId(), b.config.SessionID) {
		return errors.New("validator pubkey share request session ID mismatch", z.Str("peer_id", peerID.String()))
	}

	ppk := NodePubKeys{
		PeerID: peerID,
		PubKey: protoMsg.GetPublicKey(),
	}
	if protoMsg.GetShares() != nil {
		ppk.PubKeyShares = protoMsg.GetShares().GetPublicKeyShares()
	}

	select {
	case <-ctx.Done():
		log.Error(ctx, "Dropping node pubkey, context done", nil, z.Str("from", peerID.String()))
	case b.nodePubKeysCh <- ppk:
	}

	return nil
}

func (b *Board) handleValidatorPubKeyShareMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoMsg, ok := msg.(*pb.ValidatorPubKeyShareMessage)
	if !ok {
		return nil, false, errors.New("validator pubkey share request malformed", z.Str("peer_id", peerID.String()))
	}

	if !bytes.Equal(protoMsg.GetSessionId(), b.config.SessionID) {
		return nil, false, errors.New("validator pubkey share request session ID mismatch", z.Str("peer_id", peerID.String()))
	}

	vpks := ValidatorPubKeyShare{
		PeerID:          peerID,
		ValidatorPubKey: protoMsg.GetPublicKeyShare(),
	}

	select {
	case b.valPubKeySharesCh <- vpks:
	case <-ctx.Done():
		log.Error(b.logCtx, "Dropping validator pubkey share, context done", nil, z.Str("from", peerID.String()))
		return nil, false, errors.Wrap(ctx.Err(), "response data is not consumed")
	}

	return nil, true, nil
}

func (b *Board) handleDealBundleMessage(ctx context.Context, peerID peer.ID, msg proto.Message) (proto.Message, bool, error) {
	protoBundle, ok := msg.(*pb.PedersenDealBundle)
	if !ok {
		return nil, false, errors.New("deal bundle request malformed", z.Str("peer_id", peerID.String()))
	}

	// Drop identical re-deliveries: kyber evicts a dealer when it sees a duplicate bundle.
	if b.dedup.isDuplicate(dealBundleMsg, protoBundle.GetSignature()) {
		log.Debug(b.logCtx, "Dropping duplicate deal bundle", z.Str("from", peerID.String()))
		return nil, true, nil
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

	// Drop identical re-deliveries: kyber evicts a share holder when it sees a duplicate bundle.
	if b.dedup.isDuplicate(respBundleMsg, protoBundle.GetSignature()) {
		log.Debug(b.logCtx, "Dropping duplicate response bundle", z.Str("from", peerID.String()))
		return nil, true, nil
	}

	bundle, err := ResponseBundleFromProto(protoBundle)
	if err != nil {
		return nil, false, errors.Wrap(err, "response bundle request invalid", z.Str("peer_id", peerID.String()))
	}

	logComplaints(b.logCtx, "Received DKG complaints, this peer rejected deals from these dealers", peerID, bundle)

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

	// Drop identical re-deliveries: kyber evicts a dealer when it sees a duplicate bundle.
	if b.dedup.isDuplicate(justBundleMsg, protoBundle.GetSignature()) {
		log.Debug(b.logCtx, "Dropping duplicate justification bundle", z.Str("from", peerID.String()))
		return nil, true, nil
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

// logComplaints surfaces complaint responses which kyber processes silently. A complaint
// means the sender could not verify a dealer's deal (e.g. undecryptable share or a share
// inconsistent with the cluster's public commitments).
func logComplaints(ctx context.Context, msg string, peerID peer.ID, bundle kdkg.ResponseBundle) {
	var dealers []uint32

	for _, resp := range bundle.Responses {
		if resp.Status == kdkg.Complaint {
			dealers = append(dealers, resp.DealerIndex)
		}
	}

	if len(dealers) == 0 {
		return
	}

	log.Warn(ctx, msg, nil,
		z.Str("peer_id", peerID.String()),
		z.U64("share_index", uint64(bundle.ShareIndex)),
		z.Any("dealer_indices", dealers))
}

// bundleDedup drops byte-identical re-deliveries of DKG bundles. Bundles are keyed by
// their signature, which is unique per dealer, content and session.
type bundleDedup struct {
	mu   sync.Mutex
	seen map[[32]byte]struct{}
}

func newBundleDedup() *bundleDedup {
	return &bundleDedup{seen: make(map[[32]byte]struct{})}
}

// isDuplicate returns true if a bundle of this type with this signature was already delivered,
// and records it otherwise.
func (d *bundleDedup) isDuplicate(msgType string, signature []byte) bool {
	h := sha256.Sum256(append([]byte(msgType), signature...))

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.seen[h]; ok {
		return true
	}

	d.seen[h] = struct{}{}

	return false
}

// forwardBundles forwards bundles from in to out until ctx is canceled, then closes out.
// Kyber FastSync protocol goroutines exit when a board channel closes, so this stops
// them without modifying the kyber library.
func forwardBundles[T any](ctx context.Context, in <-chan T, out chan<- T) {
	defer close(out)

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-in:
			select {
			case out <- msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

func checkNodePubKeyMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg pb.NodePubKeyMessage

	if err := msgAny.UnmarshalTo(&msg); err != nil {
		return errors.Wrap(err, "pubkey request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}
