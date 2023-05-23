// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"crypto/sha256"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/p2p"
)

// Component is the reliable-broadcast handler, in charge of signature and message
// dispatch.
type Component struct {
	BroadcastFunc BroadcastFunc

	allowedMsgIDs map[string]struct{}
	srv           *server
	secret        *k1.PrivateKey
	peers         []peer.ID
}

// Handle adds a callback for msgID.
func (c *Component) Handle(msgID string, callback Callback) {
	c.allowedMsgIDs[msgID] = struct{}{}
	c.srv.registerCallback(msgID, callback)
}

// New registers a new reliable-broadcast server and returns a reliable-broadcast client function.
func New(tcpNode host.Host, peers []peer.ID, secret *k1.PrivateKey) *Component {
	c := Component{
		allowedMsgIDs: map[string]struct{}{},
		secret:        secret,
		peers:         peers,
	}

	signFunc := c.newK1Signer()
	verifyFunc := c.newPeerK1Verifier()

	cl := newClient(tcpNode, peers, p2p.SendReceive, p2p.Send, hashAny, signFunc, verifyFunc)

	c.BroadcastFunc = cl.Broadcast
	c.srv = newServer(tcpNode, signFunc, verifyFunc)

	return &c
}

// hashAny is a function that hashes a any-wrapped protobuf message.
func hashAny(anyPB *anypb.Any) ([]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(anyPB.TypeUrl))
	_, _ = h.Write(anyPB.Value)

	return h.Sum(nil), nil
}

// newK1Signer returns a function that signs a hash using the given private key.
func (c *Component) newK1Signer() func(string, []byte) ([]byte, error) {
	return func(msgID string, hash []byte) ([]byte, error) {
		if _, ok := c.allowedMsgIDs[msgID]; !ok {
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

		if _, ok := c.allowedMsgIDs[msgID]; !ok {
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

			if ok, err := k1util.Verify(pubkey, hash, sig[:64]); err != nil {
				return errors.Wrap(err, "verify failed")
			} else if !ok {
				return errors.New("invalid signature")
			}
		}

		return nil
	}
}
