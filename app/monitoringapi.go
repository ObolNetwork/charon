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
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/p2p"
)

// newReadyHandler returns a http.HandlerFunc which returns 200 when both the beacon node is synced and all quorum peers can be pinged  in parallel within a timeout. Returns 500 otherwise.
func newReadyHandler(ctx context.Context, conf Config, life *lifecycle.Manager, tcpNode host.Host, lock cluster.Lock) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eth2Svc, _, err := newETH2Client(ctx, conf, life, nil)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Couldn't initialize ETH2 client")
		}

		eth2Cl := eth2Svc.(eth2client.NodeSyncingProvider)
		syncing, err := beaconNodeSyncing(ctx, eth2Cl)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Failed to get beacon sync state")
		}

		if syncing {
			writeResponse(w, http.StatusInternalServerError, "Beacon node not synced")
			return
		}

		peers, err := lock.Peers()
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Peers not found")
			return
		}

		err = peersReady(ctx, peers, tcpNode)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Couldn't ping all peers")
			return
		}

		writeResponse(w, http.StatusOK, "ok")
	}
}

// beaconNodeSyncing returns true if the beacon node is still syncing.
func beaconNodeSyncing(ctx context.Context, eth2Cl eth2client.NodeSyncingProvider) (bool, error) {
	state, err := eth2Cl.NodeSyncing(ctx)
	if err != nil {
		return false, err
	}

	return state.IsSyncing, nil
}

// peersReady returns nil if all quorum peers can be pinged in parallel within a timeout. Returns error otherwise.
func peersReady(ctx context.Context, peers []p2p.Peer, tcpNode host.Host) error {
	pingCnt := 0
	results := make(chan ping.Result, len(peers))

	// ping all quorum peers in parallel
	for _, p := range peers {
		if tcpNode.ID() == p.ID {
			continue // don't ping self
		}

		go func(pID peer.ID) {
			for result := range ping.Ping(ctx, tcpNode, pID) {
				results <- result

				break // no retries, just break on first ping result
			}
		}(p.ID)
	}

	for {
		select {
		case res := <-results:
			if res.Error != nil {
				return res.Error
			}

			pingCnt++

			if pingCnt == len(peers)-1 { // all pings successful
				return nil
			}
		case <-time.After(1 * time.Second):
			return errors.New("peer pinging timed out")
		}
	}
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
