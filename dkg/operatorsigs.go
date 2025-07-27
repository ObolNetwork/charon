// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg/bcast"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const operatorSigMsgID = "/charon/dkg/operator_sig"

func operatorSigMsgIDs() []string {
	return []string{operatorSigMsgID}
}

// operatorSigBcast handles broadcasting of EIP712 signatures over the Operator via the bcast protocol.
type operatorSigBcast struct {
	sigs     []*operatorSigTuple
	sigsLock sync.Mutex

	bcastFunc bcast.BroadcastFunc
	peers     []p2p.Peer
	nodeIdx   cluster.NodeIdx
}

type operatorSigTuple struct {
	creatorSig    []byte
	configHashSig []byte
	enrSig        []byte
}

// newOperatorSigBcast returns a new instance of operatorSigBcast.
// It registers bcast handlers on bcastComp.
func newOperatorSigBcast(
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
) *operatorSigBcast {
	ret := &operatorSigBcast{
		sigs:      make([]*operatorSigTuple, len(peers)),
		bcastFunc: bcastComp.Broadcast,
		peers:     peers,
		nodeIdx:   nodeIdx,
	}

	for _, msgID := range operatorSigMsgIDs() {
		bcastComp.RegisterMessageIDFuncs(msgID, ret.broadcastCallback, ret.checkMessage)
	}

	return ret
}

// allSigs returns true if all the node signatures have been received.
// It is safe to use concurrently.
func (n *operatorSigBcast) allSigs() ([]operatorSigTuple, bool) {
	n.sigsLock.Lock()
	defer n.sigsLock.Unlock()

	for _, sig := range n.sigs {
		if sig == nil {
			return nil, false
		}
	}

	// make a hard copy of the signatures
	ret := make([]operatorSigTuple, len(n.sigs))
	for i, sig := range n.sigs {
		ret[i].creatorSig = make([]byte, len(sig.creatorSig))
		copy(ret[i].creatorSig, sig.creatorSig)
		ret[i].configHashSig = make([]byte, len(sig.configHashSig))
		copy(ret[i].configHashSig, sig.configHashSig)
		ret[i].enrSig = make([]byte, len(sig.enrSig))
		copy(ret[i].enrSig, sig.enrSig)
	}

	return ret, true
}

// setSig sets sig into n.sigs at the given array slot.
// It is safe to use concurrently.
func (n *operatorSigBcast) setSig(ost *operatorSigTuple, slot int) {
	n.sigsLock.Lock()
	defer n.sigsLock.Unlock()

	n.sigs[slot] = ost
}

// broadcastCallback is the default bcast.Callback for operatorSigBcast.
func (n *operatorSigBcast) broadcastCallback(_ context.Context, _ peer.ID, _ string, msg proto.Message) error {
	operatorSig, ok := msg.(*dkgpb.MsgOperatorSig)
	if !ok {
		return errors.New("invalid node sig type")
	}

	creatorSig := operatorSig.GetCreatorSignature()
	configSig := operatorSig.GetConfigSignature()
	enrSig := operatorSig.GetEnrSignature()
	msgPeerIdx := int(operatorSig.GetPeerIndex())

	if (msgPeerIdx == n.nodeIdx.PeerIdx) || (msgPeerIdx < 0 || msgPeerIdx >= len(n.peers)) {
		return errors.New("invalid peer index")
	}

	n.setSig(&operatorSigTuple{
		creatorSig:    creatorSig,
		configHashSig: configSig,
		enrSig:        enrSig,
	}, msgPeerIdx)

	return nil
}

// checkMessage is the default bcast.CheckMessage for operatorSigBcast.
func (*operatorSigBcast) checkMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg dkgpb.MsgOperatorSig

	err := msgAny.UnmarshalTo(&msg)
	if err != nil {
		return errors.Wrap(err, "operator signature request malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (n *operatorSigBcast) exchange(
	ctx context.Context,
	creatorSig []byte,
	configSig []byte,
	enrSig []byte,
) ([]operatorSigTuple, error) {
	opSigTuple := operatorSigTuple{}
	opSigTuple.configHashSig = make([]byte, len(configSig))
	copy(opSigTuple.configHashSig, configSig)
	opSigTuple.creatorSig = make([]byte, len(creatorSig))
	copy(opSigTuple.creatorSig, creatorSig)
	opSigTuple.enrSig = make([]byte, len(enrSig))
	copy(opSigTuple.enrSig, enrSig)

	bcastData := &dkgpb.MsgOperatorSig{
		CreatorSignature: creatorSig,
		ConfigSignature:  configSig,
		EnrSignature:     enrSig,
		PeerIndex:        uint32(n.nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Exchanging operator signatures")

	if err := n.bcastFunc(ctx, operatorSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "eip712 operator signatures broadcast")
	}

	n.setSig(&opSigTuple, n.nodeIdx.PeerIdx)

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
