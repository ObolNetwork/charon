// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const nodeSigMsgID = "/charon/dkg/node_sig"

var noneData = []byte{0xde, 0xad, 0xbe, 0xef}

func nodeSigMsgIDs() []string {
	return []string{nodeSigMsgID}
}

// nodeSigBcast handles broadcasting of K1 signatures over the lock hash via the bcast protocol.
type nodeSigBcast struct {
	sigs     [][]byte
	sigsLock sync.Mutex

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
		sigs:       make([][]byte, len(peers)),
		bcastFunc:  bcastComp.Broadcast,
		peers:      peers,
		nodeIdx:    nodeIdx,
		lockHashCh: make(chan []byte),
	}

	for _, k1Sig := range nodeSigMsgIDs() {
		bcastComp.RegisterMessageIDFuncs(k1Sig, ret.broadcastCallback, ret.checkMessage)
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
// It is safe to use concurrently.
func (n *nodeSigBcast) allSigs() ([][]byte, bool) {
	n.sigsLock.Lock()
	defer n.sigsLock.Unlock()

	for _, sig := range n.sigs {
		if len(sig) == 0 {
			return nil, false
		}
	}

	sigs := slices.DeleteFunc(n.sigs, func(sig []byte) bool {
		return bytes.Equal(sig, noneData)
	})

	// make a hard copy of the signatures
	ret := make([][]byte, len(sigs))
	copy(ret, sigs)

	return ret, true
}

// setSig sets sig into n.sigs at the given array slot.
// It is safe to use concurrently.
func (n *nodeSigBcast) setSig(sig []byte, slot int) {
	n.sigsLock.Lock()
	defer n.sigsLock.Unlock()

	n.sigs[slot] = sig
}

// broadcastCallback is the default bcast.Callback for nodeSigBcast.
func (n *nodeSigBcast) broadcastCallback(ctx context.Context, senderID peer.ID, _ string, msg proto.Message) error {
	nodeSig, ok := msg.(*dkgpb.MsgNodeSig)
	if !ok {
		return errors.New("invalid node sig type")
	}

	msgPeerIdx := int(nodeSig.GetPeerIndex())

	if msgPeerIdx < 0 || msgPeerIdx >= len(n.peers) {
		return errors.New("invalid peer index")
	}

	if msgPeerIdx == n.nodeIdx.PeerIdx {
		return errors.New("invalid peer index")
	}

	// Verify that the actual sender's peer ID matches the claimed peer index
	if n.peers[msgPeerIdx].ID != senderID {
		return errors.New("sender peer ID does not match claimed peer index")
	}

	sig := nodeSig.GetSignature()
	if bytes.Equal(sig, noneData) {
		// For certain protocols we allow exchanging nil signatures.
		n.setSig(noneData, msgPeerIdx)

		return nil
	}

	lockHash, err := n.lockHash(ctx)
	if err != nil {
		return errors.Wrap(err, "lock hash wait")
	}

	if bytes.Equal(lockHash, noneData) {
		n.setSig(noneData, msgPeerIdx)

		return nil
	}

	peerPubk, err := n.peers[msgPeerIdx].PublicKey()
	if err != nil {
		return errors.Wrap(err, "get peer public key")
	}

	verified, err := k1util.Verify65(peerPubk, lockHash, sig)
	if err != nil {
		return errors.Wrap(err, "verify node signature")
	} else if !verified {
		return errors.New("invalid node signature")
	}

	n.setSig(sig, msgPeerIdx)

	return nil
}

// checkMessage is the default bcast.CheckMessage for nodeSigBcast.
func (*nodeSigBcast) checkMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg dkgpb.MsgNodeSig

	err := msgAny.UnmarshalTo(&msg)
	if err != nil {
		return errors.Wrap(err, "node signature request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
// To exchange a nil signature, pass a nil key.
func (n *nodeSigBcast) exchange(
	ctx context.Context,
	key *k1.PrivateKey,
	lockHash []byte,
) ([][]byte, error) {
	var (
		localSig []byte
		err      error
	)

	if key != nil {
		localSig, err = k1util.Sign(key, lockHash)
		if err != nil {
			return nil, errors.Wrap(err, "k1 lock hash signature")
		}
	} else {
		localSig = noneData
		lockHash = noneData
	}

	go func() {
		n.lockHashCh <- lockHash
	}()

	bcastData := &dkgpb.MsgNodeSig{
		Signature: localSig,
		PeerIndex: uint32(n.nodeIdx.PeerIdx),
	}

	if err := n.bcastFunc(ctx, nodeSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	n.setSig(localSig, n.nodeIdx.PeerIdx)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			sigs, ok := n.allSigs()
			if ok {
				return sigs, nil
			}
		}
	}
}
