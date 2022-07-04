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

package app

import (
	"context"
	"net/http"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

// ready returns a http.Handler which returns 200 when both the beacon node is synced and all quorum peers can be pinged  in parallel within a timeout. Returns 500 otherwise.
func ready(ctx context.Context, conf Config, life *lifecycle.Manager, tcpNode host.Host, lock cluster.Lock) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// check if beacon node is fully synced
		syncing := beaconNodeSynced(ctx, conf, life)
		if syncing {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Beacon node is syncing"))

			return
		}

		err := peersReady(ctx, lock, tcpNode)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Couldn't ping all peers"))

			return
		}

		_, _ = w.Write([]byte("ok"))
	}
}

// beaconNodeReady returns true if the beacon node is fully synced.
func beaconNodeSynced(ctx context.Context, conf Config, life *lifecycle.Manager) bool {
	eth2Svc, _, err := newETH2Client(ctx, conf, life, nil)
	if err != nil {
		log.Error(ctx, "New eth2 client", err)
	}

	eth2Cl := eth2Svc.(eth2client.NodeSyncingProvider)
	state, err := eth2Cl.NodeSyncing(ctx)
	if err != nil {
		log.Error(ctx, "Failed to get sync state", err)
	}

	return state.IsSyncing
}

// peersReady returns nil if all quorum peers can be pinged in parallel within a timeout. Returns error otherwise.
func peersReady(ctx context.Context, lock cluster.Lock, tcpNode host.Host) error {
	peers, err := lock.Peers()
	if err != nil {
		return err
	}

	var pings []ping.Result
	pingOk := make(chan ping.Result, 1)
	pingErrs := make(chan ping.Result)

	// ping all quorum peers in parallel
	for _, p := range peers {
		if tcpNode.ID() == p.ID {
			continue // don't ping self
		}

		p := p

		go func() {
			for result := range ping.Ping(ctx, tcpNode, p.ID) {
				if result.Error != nil {
					pingErrs <- result
					log.Error(ctx, "Peer ping failed", err, z.Str("peer", p2p.PeerName(p.ID)))
				} else {
					pings = append(pings, result)
					if len(pings) == len(peers)-1 {
						pingOk <- result
					}
				}

				break
			}
		}()
	}

	for {
		select {
		case res := <-pingErrs:
			return res.Error
		case <-pingOk:
			return nil
		case <-time.After(1 * time.Second):
			return errors.New("peer pinging timed out")
		}
	}
}
