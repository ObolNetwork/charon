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

package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewRelayReserver returns a life cycle hook function that continuously
// reserves a relay circuit until the context is closed.
func NewRelayReserver(tcpNode host.Host, relay Peer) lifecycle.HookFunc {
	return func(ctx context.Context) error {
		ctx = log.WithTopic(ctx, "relay")
		ctx = log.WithCtx(ctx, z.Str("relay_peer", ShortID(relay.ID)))

		if relay.Enode.TCP() == 0 {
			log.Debug(ctx, "Relay not accessible")
			return nil
		}

		bootAddr, err := multiAddrFromIPPort(relay.Enode.IP(), relay.Enode.TCP())
		if err != nil {
			return errors.Wrap(err, "relay address")
		}

		addrInfo := peer.AddrInfo{
			ID:    relay.ID,
			Addrs: []ma.Multiaddr{bootAddr},
		}

		for ctx.Err() == nil {
			resv, err := circuit.Reserve(ctx, tcpNode, addrInfo)
			if err != nil {
				log.Warn(ctx, "Reserve relay circuit", z.Err(err))
				time.Sleep(time.Second * 5) // TODO(corver): Improve backoff

				continue
			}

			log.Debug(ctx, "Relay circuit reserved",
				z.Any("expire", resv.Expiration))

			select {
			case <-ctx.Done():
			case <-time.After(time.Until(resv.Expiration.Add(-time.Minute))):
				log.Debug(ctx, "Refreshing relay circuit reservation")
			}
		}

		return nil
	}
}
