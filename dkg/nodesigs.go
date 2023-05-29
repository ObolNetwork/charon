// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
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
	otherSigs   sync.Map
	bcastFunc   bcast.BroadcastFunc
	operatorAmt int
	peers       []p2p.Peer
	nodeIdx     cluster.NodeIdx
	lockHashFn  func() []byte
}

// newNodeSigBcast returns a new instance of nodeSigBcast with the given operatorAmt.
// It registers bcast handlers on bcastComp.
func newNodeSigBcast(
	operatorAmt int,
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
	lockHashFn func() []byte,
) *nodeSigBcast {
	ret := &nodeSigBcast{
		otherSigs:   sync.Map{},
		bcastFunc:   bcastComp.Broadcast,
		operatorAmt: operatorAmt,
		peers:       peers,
		nodeIdx:     nodeIdx,
		lockHashFn:  lockHashFn,
	}

	for _, k1Sig := range nodeSigMsgIDs() {
		bcastComp.RegisterCallback(k1Sig, ret.broadcastCallback)
	}

	return ret
}

// broadcastCallback is the default bcast.Callback for nodeSigBcast.
func (n *nodeSigBcast) broadcastCallback(ctx context.Context, peer peer.ID, _ string, msg proto.Message) error {
	response, ok := msg.(*dkgpb.MsgNodeSig)
	if !ok {
		return errors.New("invalid node sig type")
	}

	sig := response.GetSignature()
	msgPeerIdx := int(response.GetPeerIndex())

	if (msgPeerIdx == n.nodeIdx.PeerIdx) || (msgPeerIdx < 0 || msgPeerIdx > n.operatorAmt) {
		return errors.New("wrong peer index", z.Str("peer", peer.String()))
	}

	peerPubk, err := n.peers[msgPeerIdx].PublicKey()
	if err != nil {
		return errors.Wrap(err, "can't get peer public key", z.Str("peer", peer.String()))
	}

	// wait until lock hash becomes available
	for {
		var done bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			done = len(n.lockHashFn()) != 0
		}

		if done {
			break
		}
	}

	verified, err := k1util.Verify(peerPubk, n.lockHashFn(), sig[:len(sig)-1])
	if err != nil {
		return errors.Wrap(err, "dedup signature failure")
	} else if !verified {
		return errors.New("signature verification failed on peer lock hash")
	}

	n.otherSigs.Store(peer, response)

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (n *nodeSigBcast) exchange(
	ctx context.Context,
	key *k1.PrivateKey,
) ([][]byte, error) {
	sig, err := k1util.Sign(key, n.lockHashFn())
	if err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature")
	}

	bcastData := &dkgpb.MsgNodeSig{
		Signature: sig,
		PeerIndex: uint32(n.nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Exchanging node signatures")

	if err := n.bcastFunc(ctx, nodeSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	ret := make([][]byte, n.operatorAmt)
	ret[n.nodeIdx.PeerIdx] = sig

	for {
		var done bool

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			// bcast returns len(peers)-1 messages to each peer, so that senders don't get their own message
			// hence wait for operatorAmt-1 messages
			done = mapLen(&n.otherSigs) == n.operatorAmt-1
		}

		if done {
			break
		}
	}

	var rangeErr error
	n.otherSigs.Range(func(_, value any) bool {
		realValue, ok := value.(*dkgpb.MsgNodeSig)
		if !ok {
			rangeErr = errors.New("wrong object type in nodeSig")
			return false
		}

		sig := realValue.GetSignature()

		ret[realValue.GetPeerIndex()] = sig

		return true
	})

	if rangeErr != nil {
		return nil, rangeErr
	}

	return ret, nil
}

func mapLen(m *sync.Map) int {
	var total int
	m.Range(func(key, value any) bool {
		total++
		return true
	})

	return total
}
