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

package bootnode

import (
	"context"
	"crypto/ecdsa"

	relaylog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
)

// startP2P returns a started libp2p host or an error.
func startP2P(ctx context.Context, config Config, key *ecdsa.PrivateKey) (host.Host, error) {
	if config.RelayLogLevel != "" {
		if err := relaylog.SetLogLevel("relay", config.RelayLogLevel); err != nil {
			return nil, errors.Wrap(err, "set relay log level")
		}
	}

	// Increase resource limits
	limiter := rcmgr.DefaultLimits
	limiter.SystemBaseLimit.ConnsInbound = config.MaxConns
	limiter.SystemBaseLimit.FD = config.MaxConns
	limiter.TransientBaseLimit = limiter.SystemBaseLimit

	mgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limiter.Scale(1<<30, config.MaxConns))) // 1GB Memory
	if err != nil {
		return nil, errors.Wrap(err, "new resource manager")
	}

	tcpNode, err := p2p.NewTCPNode(ctx, config.P2PConfig, key, p2p.NewOpenGater(), libp2p.ResourceManager(mgr))
	if err != nil {
		return nil, errors.Wrap(err, "new tcp node")
	}

	p2p.RegisterConnectionLogger(tcpNode, nil)

	// Reservations are valid for 30min (github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay/constraints.go:14)
	relayResources := relay.DefaultResources()
	relayResources.Limit.Data = 32 * (1 << 20) // 32MB
	relayResources.MaxReservationsPerPeer = config.MaxResPerPeer
	relayResources.MaxReservationsPerIP = config.MaxResPerPeer
	relayResources.MaxReservations = config.MaxConns
	relayResources.MaxCircuits = config.MaxResPerPeer

	relayService, err := relay.New(tcpNode, relay.WithResources(relayResources))
	if err != nil {
		return nil, errors.Wrap(err, "new relay service")
	}

	go func() {
		<-ctx.Done()
		_ = tcpNode.Close()
		_ = relayService.Close()
	}()

	return tcpNode, nil
}
