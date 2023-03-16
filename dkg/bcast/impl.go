// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"
	"crypto/sha256"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/p2p"
)

// New registers a new reliable-broadcast server and returns a reliable-broadcast client function.
func New(tcpNode host.Host, sender *p2p.Sender, peers []peer.ID, secret *k1.PrivateKey, callback Callback) func(context.Context, proto.Message) error {
	signFunc := newK1Signer(secret)
	verifyFunc := newPeerK1Verifier(peers)

	_ = NewServer(tcpNode, signFunc, verifyFunc, callback)
	cl := NewClient(tcpNode, peers, sender.SendReceive, sender.SendAsync, hashAny, signFunc, verifyFunc)

	return cl.Broadcast
}

// HashFunc is a function that hashes a any-wrapped protobuf message.
func hashAny(anyPB *anypb.Any) ([]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(anyPB.TypeUrl))
	_, _ = h.Write(anyPB.Value)

	return h.Sum(nil), nil
}

// newK1Signer returns a function that signs a hash using the given private key.
func newK1Signer(secret *k1.PrivateKey) func(hash []byte) ([]byte, error) {
	return func(hash []byte) ([]byte, error) {
		return k1util.Sign(secret, hash)
	}
}

// newPeerK1Verifier returns a function that verifies a hash using the given peer IDs (public keys).
func newPeerK1Verifier(peers []peer.ID) func(*anypb.Any, [][]byte) error {
	return func(anyPB *anypb.Any, sigs [][]byte) error {
		if len(sigs) != len(peers) {
			return errors.New("invalid number of signatures")
		}

		hash, err := hashAny(anyPB)
		if err != nil {
			return errors.Wrap(err, "hash any")
		}

		for i, sig := range sigs {
			pubkey, err := p2p.PeerIDToKey(peers[i])
			if err != nil {
				return errors.Wrap(err, "peer id to key")
			}

			if ok, err := k1util.Verify(pubkey, hash, sig); err != nil {
				return errors.Wrap(err, "verify failed")
			} else if !ok {
				return errors.New("invalid signature")
			}
		}

		return nil
	}
}
