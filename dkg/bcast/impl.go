// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"crypto/sha256"
	"sync"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/p2p"
)

// Component is the reliable-broadcast handler, in charge of signature and message
// dispatch.
type Component struct {
	allowedMsgIDsMutex sync.Mutex
	allowedMsgIDs      map[string]struct{}

	srv           *server
	secret        *k1.PrivateKey
	peers         []peer.ID
	broadcastFunc BroadcastFunc
}

// RegisterMessageIDFuncs adds a callback and a check message function for msgID.
func (c *Component) RegisterMessageIDFuncs(msgID string, callback Callback, checkMessage CheckMessage) {
	c.allowedMsgIDsMutex.Lock()
	defer c.allowedMsgIDsMutex.Unlock()

	c.allowedMsgIDs[msgID] = struct{}{}
	c.srv.registerMessageIDFuncs(msgID, callback, checkMessage)
}

// msgIDAllowed returns true if msgID is an allowed message id.
func (c *Component) msgIDAllowed(msgID string) bool {
	c.allowedMsgIDsMutex.Lock()
	defer c.allowedMsgIDsMutex.Unlock()

	_, allowed := c.allowedMsgIDs[msgID]

	return allowed
}

// Broadcast broadcasts the given message and msgID to the configured peers.
func (c *Component) Broadcast(ctx context.Context, msgID string, msg proto.Message) error {
	return c.broadcastFunc(ctx, msgID, msg)
}

// New registers a new reliable-broadcast server and returns a reliable-broadcast client function.
func New(p2pNode host.Host, peers []peer.ID, secret *k1.PrivateKey) *Component {
	c := Component{
		allowedMsgIDs: map[string]struct{}{},
		secret:        secret,
		peers:         peers,
	}

	signFunc := c.newK1Signer()
	verifyFunc := c.newPeerK1Verifier()

	cl := newClient(p2pNode, peers, p2p.SendReceive, p2p.Send, hashAny, signFunc, verifyFunc)

	c.broadcastFunc = cl.Broadcast
	c.srv = newServer(p2pNode, signFunc, hashAny, verifyFunc)

	return &c
}

// hashAny is a function that hashes a any-wrapped protobuf message.
func hashAny(anyPB *anypb.Any) ([]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(anyPB.GetTypeUrl()))
	_, _ = h.Write(anyPB.GetValue())

	return h.Sum(nil), nil
}

// newK1Signer returns a function that signs a hash using the given private key.
func (c *Component) newK1Signer() func(string, []byte) ([]byte, error) {
	return func(msgID string, hash []byte) ([]byte, error) {
		if !c.msgIDAllowed(msgID) {
			return nil, errors.New("invalid message id")
		}

		return k1util.Sign(c.secret, hash)
	}
}

// newPeerK1Verifier returns a function that verifies a hash using the given peer IDs (public keys).
func (c *Component) newPeerK1Verifier() func(string, *anypb.Any, [][]byte) error {
	return func(msgID string, anyPB *anypb.Any, sigs [][]byte) error {
		if len(sigs) != len(c.peers) {
			return errors.New("invalid number of signatures")
		}

		if !c.msgIDAllowed(msgID) {
			return errors.New("invalid message id")
		}

		hash, err := hashAny(anyPB)
		if err != nil {
			return errors.Wrap(err, "hash any")
		}

		for i, sig := range sigs {
			pubkey, err := p2p.PeerIDToKey(c.peers[i])
			if err != nil {
				return errors.Wrap(err, "peer id to key")
			}

			if len(sig) != 65 {
				return errors.New("invalid signature length, expect 65 bytes [R || S || V] format")
			}

			if ok, err := k1util.Verify65(pubkey, hash, sig); err != nil {
				return errors.Wrap(err, "verify failed")
			} else if !ok {
				return errors.New("invalid signature")
			}
		}

		return nil
	}
}
