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

const bcastK1SigMsgID = "/charon/dkg/lock_hash_k1_sig"

func lockHashK1MsgIDs() []string {
	return []string{bcastK1SigMsgID}
}

type lockHashK1Bcast struct {
	otherSigs   chan *dkgpb.MsgLockHashK1Sig
	bcastFunc   bcast.BroadcastFunc
	operatorAmt int
}

func newLockHashK1Bcast(operatorAmt int, bcastFunc bcast.BroadcastFunc) lockHashK1Bcast {
	// bcast returns len(peers)-1 messages to each peer, so that senders don't get their own message
	return lockHashK1Bcast{
		otherSigs:   make(chan *dkgpb.MsgLockHashK1Sig, operatorAmt),
		bcastFunc:   bcastFunc,
		operatorAmt: operatorAmt,
	}
}

func (lh *lockHashK1Bcast) broadcastCallback(_ context.Context, _ peer.ID, _ string, msg proto.Message) error {
	response, ok := msg.(*dkgpb.MsgLockHashK1Sig)
	if !ok {
		return errors.New("received lock hash k1 sig response of wrong type")
	}

	lh.otherSigs <- response

	return nil
}

func (lh *lockHashK1Bcast) exchange(
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
		HashSignature: lhK1sig,
		PeerIndex:     uint32(nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Broadcasting k1 lock hash signature", z.Uint("data", uint(bcastData.GetPeerIndex())))

	if err := lh.bcastFunc(ctx, bcastK1SigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	ret := make([][]byte, lh.operatorAmt)
	ret[nodeIdx.PeerIdx] = lhK1sig

	// see newLockHashK1Bcast comment
	for idx := 0; idx < lh.operatorAmt-1; idx++ {
		otherSig := <-lh.otherSigs

		log.Debug(ctx, "Got new k1 lock hash signature", z.Int("receiver", nodeIdx.PeerIdx), z.Uint("sender", uint(otherSig.GetPeerIndex())))

		ret[otherSig.GetPeerIndex()] = otherSig.GetHashSignature()
	}

	return ret, nil
}
