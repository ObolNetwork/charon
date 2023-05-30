// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const nodeSigMsgID = "/charon/dkg/node_sig"

func nodeSigMsgIDs() []string {
	return []string{nodeSigMsgID}
}

// nodeSigBcast handles broadcasting of K1 signatures over the lock hash via the bcast protocol.
type nodeSigBcast struct {
	otherSigs [][]byte
	osLock    sync.Mutex

	bcastFunc bcast.BroadcastFunc
	peers     []p2p.Peer
	nodeIdx   cluster.NodeIdx

	lockHashCh   chan []byte
	lockHashData []byte
	lhLock       sync.Mutex
}

// newNodeSigBcast returns a new instance of nodeSigBcast.
// It registers bcast handlers on bcastComp.
func newNodeSigBcast(
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
) *nodeSigBcast {
	ret := &nodeSigBcast{
		otherSigs:  make([][]byte, len(peers)),
		bcastFunc:  bcastComp.Broadcast,
		peers:      peers,
		nodeIdx:    nodeIdx,
		lockHashCh: make(chan []byte),
	}

	for _, k1Sig := range nodeSigMsgIDs() {
		bcastComp.RegisterCallback(k1Sig, ret.broadcastCallback)
	}

	return ret
}

// lockHash returns the lock hash byte array from lockHashCh.
// Once the data has been received, it stays cached in lockHashData.
func (n *nodeSigBcast) lockHash(ctx context.Context) ([]byte, error) {
	n.lhLock.Lock()
	defer n.lhLock.Unlock()

	if len(n.lockHashData) != 0 {
		return n.lockHashData, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case n.lockHashData = <-n.lockHashCh:
		return n.lockHashData, nil
	}
}

// allSigs returns true if all the node signatures have been received.
func (n *nodeSigBcast) allSigs() bool {
	n.osLock.Lock()
	defer n.osLock.Unlock()

	for _, sig := range n.otherSigs {
		if sig == nil {
			return false
		}
	}

	return true
}

// broadcastCallback is the default bcast.Callback for nodeSigBcast.
func (n *nodeSigBcast) broadcastCallback(ctx context.Context, _ peer.ID, _ string, msg proto.Message) error {
	nodeSig, ok := msg.(*dkgpb.MsgNodeSig)
	if !ok {
		return errors.New("invalid node sig type")
	}

	sig := nodeSig.GetSignature()
	msgPeerIdx := int(nodeSig.GetPeerIndex())

	if (msgPeerIdx == n.nodeIdx.PeerIdx) || (msgPeerIdx < 0 || msgPeerIdx >= len(n.peers)) {
		return errors.New("invalid peer index")
	}

	peerPubk, err := n.peers[msgPeerIdx].PublicKey()
	if err != nil {
		return errors.Wrap(err, "get peer public key")
	}

	lockHash, err := n.lockHash(ctx)
	if err != nil {
		return errors.Wrap(err, "lock hash wait")
	}

	verified, err := k1util.Verify(peerPubk, lockHash, sig[:len(sig)-1])
	if err != nil {
		return errors.Wrap(err, "verify signature")
	} else if !verified {
		return errors.New("invalid node signature")
	}

	n.osLock.Lock()
	n.otherSigs[msgPeerIdx] = sig
	n.osLock.Unlock()

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (n *nodeSigBcast) exchange(
	ctx context.Context,
	key *k1.PrivateKey,
	lockHash []byte,
) ([][]byte, error) {
	localSig, err := k1util.Sign(key, lockHash)
	if err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature")
	}

	go func() {
		n.lockHashCh <- lockHash
	}()

	bcastData := &dkgpb.MsgNodeSig{
		Signature: localSig,
		PeerIndex: uint32(n.nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Exchanging node signatures")

	if err := n.bcastFunc(ctx, nodeSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	n.otherSigs[n.nodeIdx.PeerIdx] = localSig

	tick := time.NewTicker(100 * time.Millisecond)

	for {
		var done bool

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			done = n.allSigs()
		}

		if done {
			tick.Stop()
			break
		}
	}

	return n.otherSigs, nil
}
