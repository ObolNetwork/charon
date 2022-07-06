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
)

// newReadyHandler returns a http.HandlerFunc which returns 200 when both the beacon node is synced and all quorum peers can be pinged  in parallel within a timeout. Returns 500 otherwise.
func newReadyHandler(ctx context.Context, eth2Cl eth2client.NodeSyncingProvider, peerIDs []peer.ID, tcpNode host.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		syncing, err := beaconNodeSyncing(ctx, eth2Cl)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Failed to get beacon sync state")
		}

		if syncing {
			writeResponse(w, http.StatusInternalServerError, "Beacon node not synced")
			return
		}

		err = peersReady(ctx, peerIDs, tcpNode)
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
func peersReady(ctx context.Context, peerIDs []peer.ID, tcpNode host.Host) error {
	pingCnt := 0
	results := make(chan ping.Result, len(peerIDs))

	// ping all quorum peers in parallel
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue // don't ping self
		}

		go func(pID peer.ID) {
			for result := range ping.Ping(ctx, tcpNode, pID) {
				results <- result

				break // no retries, just break on first ping result
			}
		}(pID)
	}

	for {
		select {
		case res := <-results:
			if res.Error != nil {
				return res.Error
			}

			pingCnt++

			if pingCnt == len(peerIDs)-1 { // all pings successful
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
