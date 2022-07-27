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
	"math"
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

	mux.Handle("/readyz", newReadyHandler(tcpNode, eth2Cl, peerIDs))

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

	go func() {
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				syncing, err := beaconNodeSyncing(ctx, eth2Cl)
				if err != nil || syncing || peersReady(ctx, peerIDs, tcpNode) != nil {
					readyzGauge.Set(0)
				} else {
					readyzGauge.Set(1)
				}
			}
		}
	}()

	return nil
}

// newReadyHandler returns a http.HandlerFunc which returns 200 when both the beacon node is synced and all quorum peers can be pinged  in parallel within a timeout. Returns 500 otherwise.
func newReadyHandler(tcpNode host.Host, eth2Cl eth2client.NodeSyncingProvider, peerIDs []peer.ID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()

		var ready float64
		defer func() { readyzGauge.Set(ready) }()

		syncing, err := beaconNodeSyncing(ctx, eth2Cl)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Failed to get beacon sync state")
			return
		} else if syncing {
			writeResponse(w, http.StatusInternalServerError, "Beacon node not synced")
			return
		}

		err = peersReady(ctx, peerIDs, tcpNode)
		if err != nil {
			writeResponse(w, http.StatusInternalServerError, "Couldn't ping all peers")
			return
		}

		ready = 1
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

// peersReady returns an error if quorum peers cannot be pinged (concurrently).
func peersReady(ctx context.Context, peerIDs []peer.ID, tcpNode host.Host) error {
	results := make(chan ping.Result, len(peerIDs))
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue // Don't ping self
		}

		go func(pID peer.ID) {
			ctx, cancel := context.WithCancel(ctx) // Cancel after reading first result
			defer cancel()

			results <- <-ping.Ping(ctx, tcpNode, pID)
		}(pID)
	}

	var (
		// Require quorum successes (excluding self). Formula from IBFT 2.0 paper https://arxiv.org/pdf/1909.10194.pdf
		require = int(math.Ceil(float64(len(peerIDs)*2)/3)) - 1
		actual  int
	)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res := <-results:
			if res.Error != nil {
				continue
			}

			actual++
			if actual == require {
				return nil
			}
		}
	}
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
