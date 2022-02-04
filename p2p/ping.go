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
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// StartPingService stars a p2p ping service that pings all peers every second
// and collects metrics.
func StartPingService(host host.Host, peers []peer.ID, callback func(peer.ID)) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = log.WithTopic(ctx, "ping")

	svc := ping.PingService{Host: host}
	host.SetStreamHandler(ping.ID, func(s network.Stream) {
		s = streamSpy{
			Stream: s,
			WriteCallback: func() {
				if callback != nil {
					callback(s.Conn().RemotePeer())
				}
			},
		}
		svc.PingHandler(s)
	})

	logResult := newPingLogger(peers)

	for _, p := range peers {
		if p == host.ID() {
			// Do not ping self
			continue
		}

		go func(p peer.ID) {
			for ctx.Err() == nil {
				for result := range svc.Ping(ctx, p) {
					logResult(ctx, p, result.Error)

					if result.Error != nil {
						incPingError(p)
					} else {
						observePing(p, result.RTT)
					}

					const pingPeriod = time.Second

					time.Sleep(pingPeriod)
				}
			}
		}(p)
	}

	return cancel
}

// newPingLogger returns stateful logging function that logs ping failures
// and recoveries after applying hysteresis; only logging after N opposite results.
func newPingLogger(peers []peer.ID) func(context.Context, peer.ID, error) {
	const hysteresis = 1 // N = 5

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
		} else if prev < hysteresis && now == hysteresis && !ok {
			log.Warn(ctx, "Peer ping recovered", z.Str("peer", ShortID(p)))
			state[p] = true
		}
	}
}

// streamSpy wraps a stream and calls WriteCallback for each call to Write.
type streamSpy struct {
	network.Stream
	WriteCallback func()
}

func (s streamSpy) Write(p []byte) (n int, err error) {
	s.WriteCallback()
	return s.Stream.Write(p)
}
