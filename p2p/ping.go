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
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewPingService returns a start function of a p2p ping service that pings all peers every second
// and collects metrics.
// TODO(corver): Cluster wide req/resp doesn't scale since it is O(n^2).
func NewPingService(h host.Host, peers []peer.ID, callback func(peer.ID)) func(context.Context) {
	svc := ping.NewPingService(h)
	logFunc := newPingLogger(peers)

	return func(ctx context.Context) {
		ctx = log.WithTopic(ctx, "ping")

		for _, p := range peers {
			if p == h.ID() {
				// Do not ping self
				continue
			}

			go pingPeer(ctx, svc, p, logFunc, callback)
		}
	}
}

// pingPeer starts (and restarts) a long-lived ping service stream, pinging the peer every second until some error.
// It returns when the context is cancelled.
func pingPeer(ctx context.Context, svc *ping.PingService, p peer.ID,
	logFunc func(context.Context, peer.ID, ping.Result), callback func(peer.ID),
) {
	for ctx.Err() == nil {
		pingPeerOnce(ctx, svc, p, logFunc, callback)

		const backoff = time.Second
		time.Sleep(backoff)
	}
}

// pingPeerOnce starts a long lived ping connection with the peer and returns on first error.
func pingPeerOnce(ctx context.Context, svc *ping.PingService, p peer.ID,
	logFunc func(context.Context, peer.ID, ping.Result), callback func(peer.ID),
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for result := range svc.Ping(ctx, p) {
		if isRelayError(result.Error) || errors.Is(result.Error, context.Canceled) {
			// Just exit if relay error or context cancelled.
			return
		}

		logFunc(ctx, p, result)

		if result.Error != nil {
			incPingError(p)
			// Manually exit on first error since some error (like resource scoped closed)
			// result in ping just hanging.
			return
		}

		observePing(p, result.RTT)
		if callback != nil {
			callback(p)
		}
	}
}

// isRelayError returns true if the error is due to temporary relay circuit recycling.
func isRelayError(err error) bool {
	return errors.Is(err, network.ErrReset) ||
		errors.Is(err, network.ErrResourceScopeClosed)
}

// newPingLogger returns stateful logging function that logs ping failures
// and recoveries after applying hysteresis; only logging after N opposite results.
func newPingLogger(peers []peer.ID) func(context.Context, peer.ID, ping.Result) {
	const hysteresis = 5 // N = 5

	var (
		mu     sync.Mutex
		first  = make(map[peer.ID]bool)  // first indicates if the peer has logged anything.
		state  = make(map[peer.ID]bool)  // state indicates if the peer is ok or not
		counts = make(map[peer.ID]int)   // counts indicates number of successful pings; 0 <= x <= hysteresis
		errs   = make(map[peer.ID]error) // errs contains last non-dial backoff error
	)

	for _, p := range peers {
		state[p] = true
		counts[p] = hysteresis
		errs[p] = swarm.ErrDialBackoff // This will be over-written with no-dial-backoff errors if any.
	}

	return func(ctx context.Context, p peer.ID, result ping.Result) {
		mu.Lock()
		defer mu.Unlock()

		prev := counts[p]

		if result.Error != nil && prev > 0 {
			counts[p]-- // Decrease success count since ping failed.
		} else if result.Error == nil && prev < hysteresis {
			counts[p]++ // Increase success count since ping succeeded.
		}

		if result.Error != nil && !errors.Is(result.Error, swarm.ErrDialBackoff) {
			errs[p] = result.Error // Dial backoff errors are not informative, cache others.
		}

		now := counts[p]
		ok := state[p]

		if prev > 0 && now == 0 && ok {
			log.Warn(ctx, "Peer ping failing", nil, z.Str("peer", PeerName(p)), z.Str("error", errs[p].Error()))
			state[p] = false
			first[p] = true
		} else if prev < hysteresis && now == hysteresis && !ok {
			log.Info(ctx, "Peer ping recovered", z.Str("peer", PeerName(p)), z.Any("rtt", result.RTT))
			state[p] = true
		} else if result.Error == nil && !first[p] {
			log.Info(ctx, "Peer ping success", z.Str("peer", PeerName(p)), z.Any("rtt", result.RTT))
			first[p] = true
		}
	}
}
