// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// StartPingService stars a p2p ping service that pings all peers every second
// and collects metrics.
// TODO(corver): Cluster wide req/resp doesn't scale since it is O(n^2).
func StartPingService(h host.Host, peers []peer.ID, callback func(peer.ID)) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = log.WithTopic(ctx, "ping")

	svc := ping.NewPingService(h)
	logFunc := newPingLogger(peers)

	for _, p := range peers {
		if p == h.ID() {
			// Do not ping self
			continue
		}

		go pingPeer(ctx, svc, p, logFunc, callback)
	}

	return cancel
}

// pingPeer starts (and restarts) a long-lived ping service stream, pinging the peer every second until some error.
// It returns when the context is cancelled.
func pingPeer(ctx context.Context, svc *ping.PingService, p peer.ID,
	logFunc func(context.Context, peer.ID, error), callback func(peer.ID),
) {
	for ctx.Err() == nil {
		for result := range svc.Ping(ctx, p) {
			if errors.Is(result.Error, context.Canceled) {
				// Just exit if context cancelled.
				break
			}

			logFunc(ctx, p, result.Error)

			if result.Error != nil {
				incPingError(p)
			} else {
				observePing(p, result.RTT)
				if callback != nil {
					callback(p)
				}
			}

			const pingPeriod = time.Second

			time.Sleep(pingPeriod)
		}
	}
}

// newPingLogger returns stateful logging function that logs ping failures
// and recoveries after applying hysteresis; only logging after N opposite results.
func newPingLogger(peers []peer.ID) func(context.Context, peer.ID, error) {
	const hysteresis = 5 // N = 5

	first := make(map[peer.ID]bool) // first indicates if the peer has logged anything.
	state := make(map[peer.ID]bool) // state indicates if the peer is ok or not
	counts := make(map[peer.ID]int)
	for _, p := range peers {
		state[p] = true
		counts[p] = hysteresis
	}

	return func(ctx context.Context, p peer.ID, err error) {
		prev := counts[p]

		if err != nil && prev > 0 {
			counts[p]--
		} else if err == nil && prev < hysteresis {
			counts[p]++
		}

		now := counts[p]
		ok := state[p]

		if prev > 0 && now == 0 && ok {
			log.Warn(ctx, "Peer ping failing", z.Str("peer", ShortID(p)), z.Str("error", err.Error()))
			state[p] = false
			first[p] = true
		} else if prev < hysteresis && now == hysteresis && !ok {
			log.Info(ctx, "Peer ping recovered", z.Str("peer", ShortID(p)))
			state[p] = true
		} else if err == nil && !first[p] {
			log.Info(ctx, "Peer ping success", z.Str("peer", ShortID(p)))
			first[p] = true
		}
	}
}
