// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/hex"

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

const nodeSigMsgID = "/charon/dkg/node_sig"

func nodeSigMsgIDs() []string {
	return []string{nodeSigMsgID}
}

// nodeSigBcast handles broadcasting of K1 signatures over the lock hash via the bcast protocol.
type nodeSigBcast struct {
	otherSigs   chan *dkgpb.MsgNodeSig
	bcastFunc   bcast.BroadcastFunc
	operatorAmt int
}

// newNodeSigBcast returns a new instance of nodeSigBcast with the given operatorAmt.
// It registers bcast handlers on bcastComp.
func newNodeSigBcast(operatorAmt int, bcastComp *bcast.Component) nodeSigBcast {
	ret := nodeSigBcast{
		// bcast returns len(peers)-1 messages to each peer, so that senders don't get their own message
		// hence wait for operatorAmt-1 messages
		otherSigs:   make(chan *dkgpb.MsgNodeSig),
		bcastFunc:   bcastComp.Broadcast,
		operatorAmt: operatorAmt,
	}

	for _, k1Sig := range nodeSigMsgIDs() {
		bcastComp.RegisterCallback(k1Sig, ret.broadcastCallback)
	}

	return ret
}

// broadcastCallback is the default bcast.Callback for nodeSigBcast.
func (n *nodeSigBcast) broadcastCallback(ctx context.Context, _ peer.ID, _ string, msg proto.Message) error {
	response, ok := msg.(*dkgpb.MsgNodeSig)
	if !ok {
		return errors.New("invalid node sig type")
	}

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "nodeSigs exchange")
	case n.otherSigs <- response:
	}

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (n *nodeSigBcast) exchange(
	ctx context.Context,
	lockHash []byte,
	key *k1.PrivateKey,
	peerKeys []*k1.PublicKey,
	nodeIdx cluster.NodeIdx,
) ([][]byte, error) {
	sig, err := k1util.Sign(key, lockHash)
	if err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature")
	}

	bcastData := &dkgpb.MsgNodeSig{
		Signature: sig,
		PeerIndex: uint32(nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Exchanging node signatures")

	if err := n.bcastFunc(ctx, nodeSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "k1 lock hash signature broadcast")
	}

	dedup := make(map[string]*dkgpb.MsgNodeSig)

	ret := make([][]byte, n.operatorAmt)
	ret[nodeIdx.PeerIdx] = sig

	// see newNodeSigBcast comment
	for len(dedup) != n.operatorAmt-1 {
		select {
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "nodeSigs exchange")
		case otherSig := <-n.otherSigs:
			dedup[hex.EncodeToString(otherSig.Signature)] = otherSig

			// TODO: remove if appears too verbose down the line
			log.Debug(ctx, "Received node signature", z.Uint("sender", uint(otherSig.GetPeerIndex())))
		}
	}

	for _, elem := range dedup {
		eidx := int(elem.GetPeerIndex())
		if eidx == nodeIdx.PeerIdx {
			// ignore, someone tried to send us a signature with our index
			continue
		}

		if eidx < 0 || eidx > n.operatorAmt {
			// ignore, element index is malformed
			continue
		}

		sig := elem.GetSignature()

		verified, err := k1util.Verify(peerKeys[eidx], lockHash, sig[:len(sig)-1])
		if err != nil {
			return nil, errors.Wrap(err, "dedup signature failure")
		} else if !verified {
			return nil, errors.New("signature verification failed on peer lock hash")
		}

		ret[eidx] = sig
	}

	return ret, nil
}
