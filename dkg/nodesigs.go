// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"

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
)

const nodeSigMsgID = "/charon/dkg/lock_hash_k1_sig"

func nodeSigMsgIDs() []string {
	return []string{nodeSigMsgID}
}

// nodeSigBcast handles broadcasting of K1 signatures over the lock hash via the bcast protocol.
type nodeSigBcast struct {
	otherSigs   chan *dkgpb.MsgLockHashK1Sig
	bcastFunc   bcast.BroadcastFunc
	operatorAmt int
}

// newNodeSigBcast returns a new instance of nodeSigBcast with the given operatorAmt.
// It registers bcast handlers on bcastComp.
func newNodeSigBcast(operatorAmt int, bcastComp *bcast.Component) nodeSigBcast {
	// bcast returns len(peers)-1 messages to each peer, so that senders don't get their own message
	ret := nodeSigBcast{
		otherSigs:   make(chan *dkgpb.MsgLockHashK1Sig, operatorAmt),
		bcastFunc:   bcastComp.Broadcast,
		operatorAmt: operatorAmt,
	}

	for _, k1Sig := range nodeSigMsgIDs() {
		bcastComp.RegisterCallback(k1Sig, ret.broadcastCallback)
	}

	return ret
}

// broadcastCallback is the default bcast.Callback for nodeSigBcast.
func (lh *nodeSigBcast) broadcastCallback(_ context.Context, _ peer.ID, _ string, msg proto.Message) error {
	response, ok := msg.(*dkgpb.MsgLockHashK1Sig)
	if !ok {
		return errors.New("received lock hash k1 sig response of wrong type")
	}

	lh.otherSigs <- response

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (lh *nodeSigBcast) exchange(
	ctx context.Context,
	lockHash []byte,
	key *k1.PrivateKey,
	nodeIdx cluster.NodeIdx,
) ([][]byte, error) {
	lhK1sig, err := k1util.Sign(key, lockHash)
	if err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature")
	}

	bcastData := &dkgpb.MsgLockHashK1Sig{
		Signature: lhK1sig,
		PeerIndex: uint32(nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Broadcasting k1 lock hash signature", z.Int("source", nodeIdx.PeerIdx))

	if err := lh.bcastFunc(ctx, nodeSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	ret := make([][]byte, lh.operatorAmt)
	ret[nodeIdx.PeerIdx] = lhK1sig

	// see newLockHashK1Bcast comment
	for idx := 0; idx < lh.operatorAmt-1; idx++ {
		otherSig := <-lh.otherSigs

		// TODO: remove if appears too verbose down the line
		log.Debug(ctx, "Got new k1 lock hash signature", z.Int("receiver", nodeIdx.PeerIdx), z.Uint("sender", uint(otherSig.GetPeerIndex())))

		ret[otherSig.GetPeerIndex()] = otherSig.GetSignature()
	}

	return ret, nil
}
