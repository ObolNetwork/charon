// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// proposerConfigContentMsgID is the content agreement message ID of the lock-changing edits.
// The DKG seed check uses "/charon/dkg/proposer_config_seed", declared where it is wired.
const proposerConfigContentMsgID = "/charon/dkg/proposer_config_content"

// peerContent is a peer's proposer config content, nil when it adopts.
type peerContent struct {
	content *proposerconfig.Content
}

// contentAgreement makes all nodes agree on one proposer config content via the bcast protocol.
// Nodes without a content adopt the agreed one. An instance is single-use per ceremony: the first
// content received from each peer wins.
type contentAgreement struct {
	bcastFunc bcast.BroadcastFunc
	peers     []p2p.Peer
	nodeIdx   cluster.NodeIdx
	msgID     string

	mu       sync.Mutex
	received map[int]peerContent
}

// newContentAgreement returns a new contentAgreement and registers its bcast handlers for msgID on bcastComp.
// The bcast read limit of 128MB per message comfortably fits the content of thousands of validators.
func newContentAgreement(
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
	msgID string,
) *contentAgreement {
	ret := &contentAgreement{
		bcastFunc: bcastComp.Broadcast,
		peers:     peers,
		nodeIdx:   nodeIdx,
		msgID:     msgID,
		received:  make(map[int]peerContent),
	}

	bcastComp.RegisterMessageIDFuncs(msgID, ret.broadcastCallback, ret.checkMessage)

	return ret
}

// set stores the peer's normalised content, first write wins: an identical repeat is ignored and a
// differing one is an error. It is safe to use concurrently.
func (a *contentAgreement) set(peerIdx int, content *proposerconfig.Content) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	prev, ok := a.received[peerIdx]
	if !ok {
		a.received[peerIdx] = peerContent{content: content}
		return nil
	}

	same, err := sameOptionalContent(prev.content, content)
	if err != nil {
		return err
	}

	if !same {
		return errors.New("conflicting proposer config content from peer", z.Int("peer", peerIdx))
	}

	return nil
}

// sameOptionalContent returns whether a and b are both nil or have equal canonical hashes.
func sameOptionalContent(a, b *proposerconfig.Content) (bool, error) {
	if a == nil || b == nil {
		return a == b, nil
	}

	ha, err := proposerconfig.Document{Content: *a}.Hash()
	if err != nil {
		return false, errors.Wrap(err, "hash proposer config content")
	}

	hb, err := proposerconfig.Document{Content: *b}.Hash()
	if err != nil {
		return false, errors.Wrap(err, "hash proposer config content")
	}

	return ha == hb, nil
}

// all returns the contents of all peers once every peer's has arrived.
func (a *contentAgreement) all() ([]peerContent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.received) != len(a.peers) {
		return nil, false
	}

	res := make([]peerContent, len(a.peers))
	for idx, pc := range a.received {
		res[idx] = pc
	}

	return res, true
}

// broadcastCallback is the bcast.Callback of contentAgreement.
func (a *contentAgreement) broadcastCallback(_ context.Context, senderID peer.ID, _ string, msg proto.Message) error {
	m, ok := msg.(*dkgpb.MsgProposerConfigContent)
	if !ok {
		return errors.New("invalid proposer config content type")
	}

	peerIdx := int(m.GetPeerIndex())
	if peerIdx < 0 || peerIdx >= len(a.peers) || peerIdx == a.nodeIdx.PeerIdx {
		return errors.New("invalid peer index")
	}

	if a.peers[peerIdx].ID != senderID {
		return errors.New("sender peer ID does not match claimed peer index")
	}

	if m.GetAdopt() {
		return a.set(peerIdx, nil)
	}

	var content proposerconfig.Content

	err := json.Unmarshal(m.GetContent(), &content)
	if err != nil {
		return errors.Wrap(err, "unmarshal proposer config content", z.Int("peer", peerIdx))
	}

	norm, err := proposerconfig.Normalise(content)
	if err != nil {
		return errors.Wrap(err, "normalise proposer config content", z.Int("peer", peerIdx))
	}

	return a.set(peerIdx, &norm)
}

// checkMessage is the bcast.CheckMessage of contentAgreement.
func (*contentAgreement) checkMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg dkgpb.MsgProposerConfigContent

	err := msgAny.UnmarshalTo(&msg)
	if err != nil {
		return errors.Wrap(err, "proposer config content request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}

// agree broadcasts local (nil to adopt) and returns the content all non-adopting peers agree on.
// The lock is only used to describe disagreements; hint ends a disagreement error with the operators' remedy.
func (a *contentAgreement) agree(ctx context.Context, lock cluster.Lock, local *proposerconfig.Content, hint string) (proposerconfig.Content, error) {
	msg := &dkgpb.MsgProposerConfigContent{
		Adopt:     local == nil,
		PeerIndex: uint32(a.nodeIdx.PeerIdx),
	}

	if local != nil {
		norm, err := proposerconfig.Normalise(*local)
		if err != nil {
			return proposerconfig.Content{}, errors.Wrap(err, "normalise local proposer config content")
		}

		local = &norm

		b, err := json.Marshal(local)
		if err != nil {
			return proposerconfig.Content{}, errors.Wrap(err, "marshal proposer config content")
		}

		msg.Content = b
	}

	err := a.bcastFunc(ctx, a.msgID, msg)
	if err != nil {
		return proposerconfig.Content{}, errors.Wrap(err, "proposer config content broadcast")
	}

	err = a.set(a.nodeIdx.PeerIdx, local)
	if err != nil {
		return proposerconfig.Content{}, err
	}

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return proposerconfig.Content{}, ctx.Err()
		case <-tick.C:
			contents, ok := a.all()
			if ok {
				return resolveContents(lock, contents, hint)
			}
		}
	}
}

// resolveContents returns the content all non-adopting peers share, or an error describing the
// disagreement relative to the lowest-index non-adopting peer, ending with hint.
func resolveContents(lock cluster.Lock, contents []peerContent, hint string) (proposerconfig.Content, error) {
	firstIdx := -1

	for i, pc := range contents {
		if pc.content != nil {
			firstIdx = i
			break
		}
	}

	if firstIdx < 0 {
		return proposerconfig.Content{}, errors.New("no operator has a proposer config")
	}

	first := *contents[firstIdx].content

	firstHash, err := proposerconfig.Document{Content: first}.Hash()
	if err != nil {
		return proposerconfig.Content{}, errors.Wrap(err, "hash proposer config content")
	}

	var lines []string

	for i, pc := range contents {
		if pc.content == nil || i == firstIdx {
			continue
		}

		hash, err := proposerconfig.Document{Content: *pc.content}.Hash()
		if err != nil {
			return proposerconfig.Content{}, errors.Wrap(err, "hash proposer config content", z.Int("peer", i))
		}

		if hash == firstHash {
			continue
		}

		lines = append(lines, fmt.Sprintf("peer %d differs from peer %d:", i, firstIdx))

		diffs := proposerconfig.Diff(lock, first, *pc.content)
		for _, d := range diffs {
			lines = append(lines, fmt.Sprintf("  %s: %s -> %s", d.Field, d.Old, d.New))
		}

		if len(diffs) == 0 {
			lines = append(lines, fmt.Sprintf("  contents differ outside the compared fields (hash 0x%x vs 0x%x)", firstHash, hash))
		}
	}

	if len(lines) > 0 {
		if hint != "" {
			lines = append(lines, hint)
		}

		return proposerconfig.Content{}, errors.New("proposer config mismatch between operators:\n" + strings.Join(lines, "\n"))
	}

	return first, nil
}

// proposerConfigGenesis returns the content charon run derives with no file, with the default gas limit and no builder.
func proposerConfigGenesis(ctx context.Context, lock cluster.Lock, overridesFile string) (proposerconfig.Content, error) {
	feeRecipientFunc, err := app.GenesisFeeRecipientFunc(ctx, lock, overridesFile)
	if err != nil {
		return proposerconfig.Content{}, err
	}

	doc, err := app.ProposerConfigGenesis(lock, proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit}, feeRecipientFunc)
	if err != nil {
		return proposerconfig.Content{}, err
	}

	return doc.Content, nil
}

// loadCarriedProposerConfig returns the content of this node's proposer config file to carry into a new lock,
// or genesis if the file is absent. An unloadable or invalid file is an error.
func loadCarriedProposerConfig(ctx context.Context, lock cluster.Lock, nodeIdx cluster.NodeIdx, path, overridesFile string) (proposerconfig.Content, error) {
	doc, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrNotFound) {
		log.Info(ctx, "No proposer config file, carrying over one derived from the lock and overrides", z.Str("path", path))

		return proposerConfigGenesis(ctx, lock, overridesFile)
	} else if err != nil {
		return proposerconfig.Content{}, err
	}

	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		return proposerconfig.Content{}, errors.Wrap(err, "verify proposer config file", z.Str("path", path))
	}

	return doc.Content, nil
}

// newLockProposerConfigContent returns the content for the new lock with the agreed gas limit and builder:
// the agreed fee recipients of its first numCarried validators followed by newFees, in lock order.
func newLockProposerConfigContent(lock cluster.Lock, agreed proposerconfig.Content, numCarried int, newFees []string) (proposerconfig.Content, error) {
	gasLimit, err := agreed.GasLimit()
	if err != nil {
		return proposerconfig.Content{}, err
	}

	fees := make([]string, 0, numCarried+len(newFees))
	for _, val := range lock.Validators[:numCarried] {
		// By pubkey: a new validator is absent from the agreed content and must not get its default.
		fees = append(fees, agreed.FeeRecipient("0x"+hex.EncodeToString(val.PubKey)))
	}

	return proposerconfig.NewContent(lock, append(fees, newFees...), gasLimit, agreed.DefaultConfig.Builder)
}

// exchangeProposerConfig exchanges all operators' signatures of the lock's revision 1 proposer config with the
// content and returns the verified document. Signatures arrive in peer order, which is the lock's operator order.
func exchangeProposerConfig(ctx context.Context, caster *nodeSigBcast, key *k1.PrivateKey, lock cluster.Lock, content proposerconfig.Content) (proposerconfig.Document, error) {
	doc := proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Revision: 1,
		Content:  content,
	}

	hash, err := doc.Hash()
	if err != nil {
		return proposerconfig.Document{}, err
	}

	sigs, err := caster.exchange(ctx, key, hash[:])
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "k1 proposer config signature exchange")
	}

	if len(sigs) != len(lock.Operators) {
		return proposerconfig.Document{}, errors.New("proposer config signature count mismatch", z.Int("signatures", len(sigs)), z.Int("operators", len(lock.Operators)))
	}

	for i, sig := range sigs {
		doc.Signatures = append(doc.Signatures, proposerconfig.Signature{Operator: i, Signature: sig})
	}

	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "verify signed proposer config")
	}

	return doc, nil
}

// initProposerConfig registers the proposer config agreement and signature exchange on pctx.Caster and loads this
// node's current content to carry into the new lock, unless it adopts: operators joining have no file and operators
// leaving sign nothing, so only the remaining operators must agree. Loading here fails fast, before peers connect.
func initProposerConfig(ctx context.Context, pctx *ProtocolContext, proposerConfigFile, overridesFile string, adopt bool) error {
	pctx.ProposerConfig = newContentAgreement(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster, proposerConfigContentMsgID)
	pctx.ProposerConfigSigCaster = newNodeSigBcast(pctx.Peers, pctx.ThisNodeIdx, pctx.Caster, proposerConfigSigMsgID)

	if adopt {
		return nil
	}

	// The current lock's index, it differs from ThisNodeIdx when the protocol renumbers peers.
	nodeIdx, err := pctx.Lock.NodeIdx(pctx.ThisPeerID)
	if err != nil {
		return errors.Wrap(err, "node index in current lock")
	}

	content, err := loadCarriedProposerConfig(ctx, *pctx.Lock, nodeIdx, proposerConfigFile, overridesFile)
	if err != nil {
		return err
	}

	pctx.proposerConfigLocal = &content

	return nil
}
