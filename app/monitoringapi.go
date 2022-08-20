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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/cluster"
)

var (
	errReadyUninitialised    = errors.New("ready check uninitialised")
	errReadyTooFewPeers      = errors.New("quorum peers not connected")
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
	const minNotConnected = 3 // Require three rounds of too few connected
	var (
		mu                 sync.Mutex
		readyErr           = errReadyUninitialised
		notConnectedRounds = minNotConnected // Start as not connected.
	)
	go func() {
		ticker := clock.NewTicker(10 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
				if quorumPeersConnected(peerIDs, tcpNode) {
					notConnectedRounds = 0
				} else {
					notConnectedRounds++
				}

				syncing, err := beaconNodeSyncing(ctx, eth2Cl)
				if err != nil {
					err = errReadyBeaconNodeFailed
					readyzGauge.Set(0)
				} else if syncing {
					err = errReadySyncing
					readyzGauge.Set(0)
				} else if notConnectedRounds >= minNotConnected {
					err = errReadyTooFewPeers
					readyzGauge.Set(0)
				} else {
					readyzGauge.Set(1)
				}

				mu.Lock()
				readyErr = err
				mu.Unlock()
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

// quorumPeersConnected returns true if quorum peers are currently connected.
func quorumPeersConnected(peerIDs []peer.ID, tcpNode host.Host) bool {
	var count int
	for _, pID := range peerIDs {
		if tcpNode.ID() == pID {
			continue // Don't check self
		}

		if len(tcpNode.Network().ConnsToPeer(pID)) > 0 {
			count++
		}
	}

	// Excluding self when comparing with threshold, since we need to connect to threshold - 1 no. of peers.
	return count >= cluster.Threshold(len(peerIDs))-1
}

func writeResponse(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
