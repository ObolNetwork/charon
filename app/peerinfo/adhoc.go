// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	pbv1 "github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// DoOnce returns the peer info and RTT and true of the given peer,
// or false if the peer doesn't support the protocol,
// or an error.
func DoOnce(ctx context.Context, tcpNode host.Host, peerID peer.ID) (*pbv1.PeerInfo, time.Duration, bool, error) {
	var rtt time.Duration

	rttCallback := func(d time.Duration) {
		rtt = d
	}

	req := new(pbv1.PeerInfo)
	resp := new(pbv1.PeerInfo)

	err := p2p.SendReceive(ctx, tcpNode, peerID, req, resp, protocolID2,
		p2p.WithSendReceiveRTT(rttCallback))
	if err != nil {
		return nil, 0, false, err
	}

	return resp, rtt, true, nil
}
