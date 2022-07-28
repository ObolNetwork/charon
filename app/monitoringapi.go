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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
)

var (
	errReadyPingFailing      = errors.New("couldn't ping all peers")
	errReadySyncing          = errors.New("beacon node not synced")
	errReadyBeaconNodeFailed = errors.New("failed to get beacon sync state")
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

	readyErrFunc := startReadyChecker(ctx, tcpNode, eth2Cl, peerIDs, clockwork.NewRealClock())
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		readyErr := readyErrFunc()
		if readyErr != nil {
			writeResponse(w, http.StatusInternalServerError, readyErr.Error())
			return
		}

		writeResponse(w, http.StatusOK, "ok")
	})

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

// startReadyChecker returns function which returns an error resulting from ready checks periodically.
func startReadyChecker(ctx context.Context, tcpNode host.Host, eth2Cl eth2client.NodeSyncingProvider, peerIDs []peer.ID, clock clockwork.Clock) func() error {
	var (
		mu       sync.Mutex
		readyErr error
	)
	go func() {
		ticker := clock.NewTicker(10 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
				syncing, err := beaconNodeSyncing(ctx, eth2Cl)
				if err != nil {
					mu.Lock()
					readyErr = errReadyBeaconNodeFailed
					mu.Unlock()

					readyzGauge.Set(0)
				} else if syncing {
					mu.Lock()
					readyErr = errReadySyncing
					mu.Unlock()

					readyzGauge.Set(0)
				} else if peersReady(ctx, peerIDs, tcpNode) != nil {
					mu.Lock()
					readyErr = errReadyPingFailing
					mu.Unlock()

					readyzGauge.Set(0)
				} else {
					mu.Lock()
					readyErr = nil
					mu.Unlock()

					readyzGauge.Set(1)
				}
			}
		}
	}()

	return func() error {
		mu.Lock()
		defer mu.Unlock()

		return readyErr
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
		require  = int(math.Ceil(float64(len(peerIDs)*2)/3)) - 1
		okCount  int
		errCount int
	)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res := <-results:
			if res.Error != nil {
				errCount++
			} else {
				okCount++
			}

			// Return error if we cannot reach quorum peers.
			if errCount > (len(peerIDs) - require - 1) {
				return errors.New("not enough peers")
			}

			if okCount == require {
				return nil
			}
		}
	}
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
