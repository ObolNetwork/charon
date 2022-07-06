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
	"net/http/pprof"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
)

// wireMonitoringAPI constructs the monitoring API and registers it with the life cycle manager.
// It serves prometheus metrics, pprof profiling and the runtime enr.
func wireMonitoringAPI(ctx context.Context, life *lifecycle.Manager, addr string, localNode *enode.LocalNode, tcpNode host.Host, eth2Svc eth2client.Service, peerIDs []peer.ID) error {
	mux := http.NewServeMux()

	// Serve prometheus metrics
	mux.Handle("/metrics", promhttp.Handler())

	// Serve local ENR to allow simple HTTP Get to this node to resolve it as bootnode ENR.
	mux.Handle("/enr", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, localNode.Node().String())
	}))

	// Serve monitoring endpoints
	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	eth2Cl, ok := eth2Svc.(eth2client.NodeSyncingProvider)
	if !ok {
		return errors.New("invalid eth2 service")
	}

	mux.Handle("/readyz", newReadyHandler(ctx, tcpNode, eth2Cl, peerIDs))

	// Copied from net/http/pprof/pprof.go
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, httpServeHook(server.ListenAndServe))
	life.RegisterStop(lifecycle.StopMonitoringAPI, lifecycle.HookFunc(server.Shutdown))

	return nil
}

// newReadyHandler returns a http.HandlerFunc which returns 200 when both the beacon node is synced and all quorum peers can be pinged  in parallel within a timeout. Returns 500 otherwise.
func newReadyHandler(ctx context.Context, tcpNode host.Host, eth2Cl eth2client.NodeSyncingProvider, peerIDs []peer.ID) http.HandlerFunc {
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var resultCnt int
	results := make(chan ping.Result, len(peerIDs))

	// Ping all quorum peers in parallel
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue // Don't ping self
		}

		go func(pID peer.ID) {
			for result := range ping.Ping(ctx, tcpNode, pID) {
				results <- result

				break // No retries, just break on first ping result
			}
		}(pID)
	}

	for {
		select {
		case res := <-results:
			if res.Error != nil {
				return res.Error
			}

			resultCnt++

			if resultCnt == len(peerIDs)-1 { // all pings successful
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
