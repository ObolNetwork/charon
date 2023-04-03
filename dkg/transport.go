// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

type keycastP2P struct {
	tcpNode   host.Host
	peers     []p2p.Peer
	clusterID string
}

// ServeShares serves the dealer shares to other nodes on request. It returns when the context is closed.
func (t keycastP2P) ServeShares(ctx context.Context, handler func(nodeIdx int) (msg []byte, err error)) {
	t.tcpNode.SetStreamHandler(getProtocol(t.clusterID), func(s network.Stream) {
		ctx := log.WithCtx(ctx, z.Str("peer", p2p.PeerName(s.Conn().RemotePeer())))
		defer s.Close()

		var (
			nodeIdx int
			found   bool
		)
		for i, p := range t.peers {
			if p.ID == s.Conn().RemotePeer() {
				nodeIdx = i
				found = true

				break
			}
		}
		if !found {
			log.Warn(ctx, "Ignoring stream from unknown peer", nil, z.Str("peer", p2p.PeerName(s.Conn().RemotePeer())))
			return
		}

		msg, err := handler(nodeIdx)
		if err != nil {
			log.Error(ctx, "Handler failure", err)
			return
		}

		if _, err := s.Write(msg); err != nil {
			log.Error(ctx, "Write response", err)
			return
		}
	})

	<-ctx.Done()
}

// GetShares returns the shares requested from the dealer or a context error. It retries all other errors.
func (t keycastP2P) GetShares(ctx context.Context, _ int) ([]byte, error) {
	backoff := expbackoff.New(ctx, expbackoff.WithFastConfig())
	for {
		resp, err := getSharesOnce(ctx, t.tcpNode, t.peers[0].ID, t.clusterID)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		} else if err != nil {
			log.Warn(ctx, "Failure requesting shares from dealer (will retry)", err)
			backoff()

			continue
		}

		return resp, nil
	}
}

// getSharesOnce returns the message sent from the dealer.
func getSharesOnce(ctx context.Context, tcpNode host.Host, dealer peer.ID, clusterID string) ([]byte, error) {
	s, err := tcpNode.NewStream(network.WithUseTransient(ctx, "keycast"), dealer, getProtocol(clusterID))
	if err != nil {
		return nil, errors.Wrap(err, "new stream")
	}
	defer s.Close()

	resp, err := io.ReadAll(s)
	if err != nil {
		return nil, errors.Wrap(err, "read request")
	}

	return resp, nil
}

// getProtocol returns the protocol ID including the cluster ID.
func getProtocol(clusterID string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/charon/dkg/keycast/1.0.0/%s", clusterID))
}
