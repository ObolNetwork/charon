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

const configSigMsgID = "/charon/dkg/config_sigs"

func configSigMsgIDs() []string {
	return []string{configSigMsgID}
}

// configSigBcast handles broadcasting of EIP712 config signatures via the bcast protocol.
type configSigBcast struct {
	sigs     map[int]configSigTuple
	sigsLock sync.RWMutex

	bcastFunc bcast.BroadcastFunc
	peers     []p2p.Peer
	nodeIdx   cluster.NodeIdx
}

// configSigTuple holds the signatures for a single peer.
type configSigTuple struct {
	creatorConfigSig  []byte
	operatorConfigSig []byte
	operatorEnrSig    []byte
}

// newConfigSigTuple returns a new instance of configSigTuple.
func newConfigSigTuple(creatorConfigSig, operatorConfigSig, operatorEnrSig []byte) configSigTuple {
	return configSigTuple{
		creatorConfigSig:  append([]byte(nil), creatorConfigSig...),
		operatorConfigSig: append([]byte(nil), operatorConfigSig...),
		operatorEnrSig:    append([]byte(nil), operatorEnrSig...),
	}
}

// newConfigSigBcast returns a new instance of configSigBcast.
// It registers bcast handlers on bcastComp.
func newConfigSigBcast(
	peers []p2p.Peer,
	nodeIdx cluster.NodeIdx,
	bcastComp *bcast.Component,
) *configSigBcast {
	ret := &configSigBcast{
		sigs:      make(map[int]configSigTuple, len(peers)),
		bcastFunc: bcastComp.Broadcast,
		peers:     peers,
		nodeIdx:   nodeIdx,
	}

	for _, msgID := range configSigMsgIDs() {
		bcastComp.RegisterMessageIDFuncs(msgID, ret.broadcastCallback, ret.checkMessage)
	}

	return ret
}

// allSigs returns true if all the config signatures have been received.
// It is safe to use concurrently.
func (c *configSigBcast) allSigs() ([]configSigTuple, bool) {
	c.sigsLock.RLock()
	defer c.sigsLock.RUnlock()

	if len(c.sigs) < len(c.peers) {
		return nil, false
	}

	// make a hard copy of the signatures
	ret := make([]configSigTuple, len(c.sigs))
	for i, sig := range c.sigs {
		ret[i] = newConfigSigTuple(
			sig.creatorConfigSig,
			sig.operatorConfigSig,
			sig.operatorEnrSig,
		)
	}

	return ret, true
}

// setSig sets sig into n.sigs at the given array slot.
// It is safe to use concurrently.
func (c *configSigBcast) setSig(sig configSigTuple, slot int) {
	c.sigsLock.Lock()
	defer c.sigsLock.Unlock()

	c.sigs[slot] = sig
}

// broadcastCallback is the default bcast.Callback for configSigBcast.
func (c *configSigBcast) broadcastCallback(_ context.Context, _ peer.ID, _ string, msg proto.Message) error {
	configSigMsg, ok := msg.(*dkgpb.MsgConfigSig)
	if !ok {
		return errors.New("invalid config sig type")
	}

	msgPeerIdx := int(configSigMsg.GetPeerIndex())
	if (msgPeerIdx == c.nodeIdx.PeerIdx) || (msgPeerIdx < 0 || msgPeerIdx >= len(c.peers)) {
		return errors.New("invalid peer index")
	}

	c.setSig(newConfigSigTuple(
		configSigMsg.GetCreatorConfigSig(),
		configSigMsg.GetOperatorConfigSig(),
		configSigMsg.GetOperatorEnrSig(),
	), msgPeerIdx)

	return nil
}

// checkMessage is the default bcast.CheckMessage for configSigBcast.
func (*configSigBcast) checkMessage(_ context.Context, peerID peer.ID, msgAny *anypb.Any) error {
	var msg dkgpb.MsgConfigSig

	err := msgAny.UnmarshalTo(&msg)
	if err != nil {
		return errors.Wrap(err, "config signature message malformed", z.Str("peer_id", peerID.String()))
	}

	return nil
}

// exchange exchanges K1 signatures over lock file hashes with the peers pointed by lh.bcastFunc.
func (c *configSigBcast) exchange(
	ctx context.Context,
	creatorConfigSig []byte,
	operatorConfigSig []byte,
	operatorEnrSig []byte,
) ([]configSigTuple, error) {
	st := newConfigSigTuple(creatorConfigSig, operatorConfigSig, operatorEnrSig)

	bcastData := &dkgpb.MsgConfigSig{
		CreatorConfigSig:  st.creatorConfigSig,
		OperatorConfigSig: st.operatorConfigSig,
		OperatorEnrSig:    st.operatorEnrSig,
		PeerIndex:         uint32(c.nodeIdx.PeerIdx),
	}

	log.Debug(ctx, "Exchanging config signatures")

	if err := c.bcastFunc(ctx, configSigMsgID, bcastData); err != nil {
		return nil, errors.Wrap(err, "eip712 config signatures broadcast")
	}

	c.setSig(st, c.nodeIdx.PeerIdx)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			sigs, ok := c.allSigs()
			if ok {
				return sigs, nil
			}
		}
	}
}
