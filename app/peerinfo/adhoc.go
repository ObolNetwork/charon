// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	supported, known := p2p.ProtocolSupported(tcpNode, peerID, protocolID)
	if !known || !supported {
		return nil, 0, false, nil
	}

	var rtt time.Duration
	rttCallback := func(d time.Duration) {
		rtt = d
	}

	resp := new(pbv1.PeerInfo)
	err := p2p.SendReceive(ctx, tcpNode, peerID, &pbv1.PeerInfo{}, resp, protocolID, p2p.WithSendReceiveRTT(rttCallback))
	if err != nil {
		return nil, 0, false, err
	}

	return resp, rtt, true, nil
}
