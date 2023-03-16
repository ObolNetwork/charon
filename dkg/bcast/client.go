// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// NewClient creates a new reliable-broadcast client.
func NewClient(tcpNode host.Host, peers []peer.ID, sendRecvFunc p2p.SendReceiveFunc,
	sendFunc p2p.SendFunc, hashFunc HashFunc, signFunc SignFunc, verifyFunc VerifyFunc,
) *Client {
	return &Client{
		tcpNode:      tcpNode,
		peers:        peers,
		sendRecvFunc: sendRecvFunc,
		sendFunc:     sendFunc,
		hashFunc:     hashFunc,
		signFunc:     signFunc,
		verifyFunc:   verifyFunc,
	}
}

// Client is a reliable-broadcast client.
type Client struct {
	tcpNode      host.Host
	peers        []peer.ID
	sendRecvFunc p2p.SendReceiveFunc
	sendFunc     p2p.SendFunc
	hashFunc     HashFunc
	signFunc     SignFunc
	verifyFunc   VerifyFunc
}

// Broadcast reliably-broadcasts the message to all peers (excluding self).
func (c *Client) Broadcast(ctx context.Context, msg proto.Message) error {
	// Wrap proto in any and hash it.

	anyMsg, err := anypb.New(msg)
	if err != nil {
		return errors.Wrap(err, "new any")
	}

	hash, err := c.hashFunc(anyMsg)
	if err != nil {
		return errors.Wrap(err, "hash any")
	}

	// Send hash to all peers to sign.

	sigReq := &pb.BCastSigRequest{
		Hash: hash,
	}

	fork, join, cancel := forkjoin.New(ctx, func(ctx context.Context, pID peer.ID) (*pb.BCastSigResponse, error) {
		sigResp := new(pb.BCastSigResponse)
		err := c.sendRecvFunc(ctx, c.tcpNode, pID, sigReq, sigResp, protocolIDSig, p2p.WithDelimitedProtocol(protocolIDSig))

		return sigResp, err
	})
	defer cancel()

	sigs := make([][]byte, len(c.peers))

	// Fork

	for i, pID := range c.peers {
		if c.tcpNode.ID() == pID {
			// Sign self locally.
			sig, err := c.signFunc(sigReq.Hash)
			if err != nil {
				return errors.Wrap(err, "sign hash")
			}

			sigs[i] = sig

			continue
		}

		fork(pID)
	}

	// Join

	for resp := range join() {
		if resp.Err != nil {
			return errors.Wrap(err, "send sig request", z.Str("peer", p2p.PeerName(resp.Input)))
		}

		var found bool
		for i, pID := range c.peers {
			if resp.Input == pID {
				sigs[i] = resp.Output.Signature
				found = true

				break
			}
		}

		if !found {
			return errors.New("unknown peer ID")
		}
	}

	// Verify

	if err := c.verifyFunc(anyMsg, sigs); err != nil {
		return errors.New("verify signatures")
	}

	// Broadcast message to all peers (excluding self).

	bcastMsg := &pb.BCastMessage{
		Message:    anyMsg,
		Signatures: sigs,
	}

	for _, pID := range c.peers {
		if c.tcpNode.ID() == pID {
			continue // Skip self.
		}

		err := c.sendFunc(ctx, c.tcpNode, protocolIDMsg, pID, bcastMsg, p2p.WithDelimitedProtocol(protocolIDMsg))
		if err != nil {
			return errors.Wrap(err, "send message")
		}
	}

	return nil
}
