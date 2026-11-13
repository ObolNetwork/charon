// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
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

// configAgreement makes all nodes agree on one proposer config via the bcast protocol.
// An instance is single-use per ceremony: the first config received from each peer wins.
type configAgreement struct {
	bcastFunc bcast.BroadcastFunc
	peers     []p2p.Peer
	nodeIdx   cluster.NodeIdx
	msgID     string

	mu       sync.Mutex
	received map[int]proposerconfig.Config
}

// newConfigAgreement returns a new configAgreement and registers its bcast handlers for msgID on bcastComp.
// The bcast read limit of 128MB per message comfortably fits the config of thousands of validators.
func newConfigAgreement(
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
	msgID string,
) *configAgreement {
	ret := &configAgreement{
		bcastFunc: bcastComp.Broadcast,
		peers:     peers,
		nodeIdx:   nodeIdx,
		msgID:     msgID,
		received:  make(map[int]proposerconfig.Config),
	}

	bcastComp.RegisterMessageIDFuncs(msgID, ret.broadcastCallback, ret.checkMessage)

	return ret
}

// set stores the peer's normalised config, first write wins: an identical repeat is ignored and a
// differing one is an error. It is safe to use concurrently.
func (a *configAgreement) set(peerIdx int, cfg proposerconfig.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	prev, ok := a.received[peerIdx]
	if !ok {
		a.received[peerIdx] = cfg
		return nil
	}

	same, err := proposerconfig.SameConfig(prev, cfg)
	if err != nil {
		return err
	}

	if !same {
		return errors.New("conflicting proposer config from peer", z.Int("peer", peerIdx))
	}

	return nil
}

// all returns the configs of all peers in peer order once every peer's has arrived.
func (a *configAgreement) all() ([]proposerconfig.Config, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.received) != len(a.peers) {
		return nil, false
	}

	res := make([]proposerconfig.Config, len(a.peers))
	for idx, cfg := range a.received {
		res[idx] = cfg
	}

	return res, true
}

// broadcastCallback is the bcast.Callback of configAgreement.
func (a *configAgreement) broadcastCallback(_ context.Context, senderID peer.ID, _ string, msg proto.Message) error {
	m, ok := msg.(*dkgpb.MsgProposerConfigContent)
	if !ok {
		return errors.New("invalid proposer config type")
	}

	peerIdx := int(m.GetPeerIndex())
	if peerIdx < 0 || peerIdx >= len(a.peers) || peerIdx == a.nodeIdx.PeerIdx {
		return errors.New("invalid peer index")
	}

	if a.peers[peerIdx].ID != senderID {
		return errors.New("sender peer ID does not match claimed peer index")
	}

	var cfg proposerconfig.Config

	err := json.Unmarshal(m.GetContent(), &cfg)
	if err != nil {
		return errors.Wrap(err, "unmarshal proposer config", z.Int("peer", peerIdx))
	}

	norm, err := proposerconfig.Normalise(cfg)
	if err != nil {
		return errors.Wrap(err, "normalise proposer config", z.Int("peer", peerIdx))
	}

	return a.set(peerIdx, norm)
}

// checkMessage is the bcast.CheckMessage of configAgreement.
func (*configAgreement) checkMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg dkgpb.MsgProposerConfigContent

	err := msgAny.UnmarshalTo(&msg)
	if err != nil {
		return errors.Wrap(err, "proposer config request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}

// agree broadcasts local and returns the config all peers agree on. The lock is only used to describe
// disagreements; hint ends a disagreement error with the operators' remedy.
func (a *configAgreement) agree(ctx context.Context, lock cluster.Lock, local proposerconfig.Config, hint string) (proposerconfig.Config, error) {
	norm, err := proposerconfig.Normalise(local)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "normalise local proposer config")
	}

	b, err := json.Marshal(norm)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "marshal proposer config")
	}

	msg := &dkgpb.MsgProposerConfigContent{
		Content:   b,
		PeerIndex: uint32(a.nodeIdx.PeerIdx),
	}

	err = a.bcastFunc(ctx, a.msgID, msg)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "proposer config broadcast")
	}

	err = a.set(a.nodeIdx.PeerIdx, norm)
	if err != nil {
		return proposerconfig.Config{}, err
	}

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return proposerconfig.Config{}, ctx.Err()
		case <-tick.C:
			cfgs, ok := a.all()
			if ok {
				return resolveConfigs(lock, cfgs, hint)
			}
		}
	}
}

// resolveConfigs returns the config all peers share, or an error describing each disagreement
// relative to peer 0, ending with hint.
func resolveConfigs(lock cluster.Lock, cfgs []proposerconfig.Config, hint string) (proposerconfig.Config, error) {
	first := cfgs[0]

	var lines []string

	for i, cfg := range cfgs[1:] {
		same, err := proposerconfig.SameConfig(first, cfg)
		if err != nil {
			return proposerconfig.Config{}, errors.Wrap(err, "compare proposer configs", z.Int("peer", i+1))
		}

		if same {
			continue
		}

		lines = append(lines, fmt.Sprintf("peer %d differs from peer 0:", i+1))

		diffs := proposerconfig.Diff(lock, first, cfg)
		for _, line := range diffs {
			lines = append(lines, "  "+line)
		}

		if len(diffs) == 0 {
			lines = append(lines, "  configs differ outside the compared fields")
		}
	}

	if len(lines) > 0 {
		if hint != "" {
			lines = append(lines, hint)
		}

		return proposerconfig.Config{}, errors.New("proposer config mismatch between operators:\n" + strings.Join(lines, "\n"))
	}

	return first, nil
}

// initialProposerConfig returns the config charon run derives with no file, with the default gas limit and no builder.
func initialProposerConfig(ctx context.Context, lock cluster.Lock, overridesFile string) (proposerconfig.Config, error) {
	feeRecipientFunc, err := app.RegistrationFeeRecipientFunc(ctx, lock, overridesFile)
	if err != nil {
		return proposerconfig.Config{}, err
	}

	doc, err := app.InitialProposerConfig(lock, proposerconfig.Seed{GasLimit: proposerconfig.DefaultGasLimit}, feeRecipientFunc)
	if err != nil {
		return proposerconfig.Config{}, err
	}

	return doc.Config, nil
}

// loadCarriedProposerConfig returns the config of this node's proposer config file to carry into a new lock,
// or the initial config if the file is absent. An unloadable or invalid file is an error.
func loadCarriedProposerConfig(ctx context.Context, lock cluster.Lock, nodeIdx cluster.NodeIdx, path, overridesFile string) (proposerconfig.Config, error) {
	doc, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrNotFound) {
		log.Info(ctx, "No proposer config file, carrying over one derived from the lock and overrides", z.Str("path", path))

		return initialProposerConfig(ctx, lock, overridesFile)
	} else if err != nil {
		return proposerconfig.Config{}, err
	}

	err = proposerconfig.Verify(doc, lock)
	if err != nil {
		return proposerconfig.Config{}, errors.Wrap(err, "verify proposer config file", z.Str("path", path))
	}

	return doc.Config, nil
}

// newLockProposerConfig returns the config for the new lock with the agreed gas limit and builder:
// the agreed fee recipients of the carried lock's validators followed by newFees, in lock order.
func newLockProposerConfig(lock cluster.Lock, agreed proposerconfig.Config, carried cluster.Lock, newFees []string) (proposerconfig.Config, error) {
	gasLimit, err := agreed.GasLimit()
	if err != nil {
		return proposerconfig.Config{}, err
	}

	fees := append(agreed.FeeRecipients(carried), newFees...)

	return proposerconfig.NewConfig(lock, fees, gasLimit, agreed.DefaultConfig.Builder)
}

// exchangeProposerConfig exchanges all operators' signatures of the lock's revision 1 proposer config with the
// config and returns the verified document. Signatures arrive in peer order, which is the lock's operator order.
func exchangeProposerConfig(ctx context.Context, caster *nodeSigBcast, key *k1.PrivateKey, lock cluster.Lock, cfg proposerconfig.Config) (proposerconfig.Document, error) {
	doc := proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Revision: 1,
		Config:   cfg,
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
