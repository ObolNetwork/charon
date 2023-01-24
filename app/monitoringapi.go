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
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
)

var (
	errReadyUninitialised     = errors.New("ready check uninitialised")
	errReadyInsufficientPeers = errors.New("quorum peers not connected")
	errReadyBeaconNodeSyncing = errors.New("beacon node not synced")
	errReadyBeaconNodeDown    = errors.New("beacon node down")
	errReadyVCNotConfigured   = errors.New("vc not configured")
	errReadyVCMissingVals     = errors.New("vc missing some validators")
)

// wireMonitoringAPI constructs the monitoring API and registers it with the life cycle manager.
// It serves prometheus metrics, pprof profiling and the runtime enr.
func wireMonitoringAPI(ctx context.Context, life *lifecycle.Manager, addr string,
	tcpNode host.Host, eth2Cl eth2wrap.Client,
	peerIDs []peer.ID, registry *prometheus.Registry, qbftDebug http.Handler,
	pubkeys []core.PubKey, seenPubkeys chan core.PubKey,
) {
	peerCounter(ctx, eth2Cl, clockwork.NewRealClock())

	mux := http.NewServeMux()

	// Serve prometheus metrics wrapped with cluster and node identifiers.
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	))

	// Serve monitoring endpoints
	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	readyErrFunc := startReadyChecker(ctx, tcpNode, eth2Cl, peerIDs, clockwork.NewRealClock(), pubkeys, seenPubkeys)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		readyErr := readyErrFunc()
		if readyErr != nil {
			writeResponse(w, http.StatusInternalServerError, readyErr.Error())
			return
		}

		writeResponse(w, http.StatusOK, "ok")
	})

	// Serve sniffed qbft instances messages in gzipped protobuf format.
	mux.Handle("/debug/qbft", qbftDebug)

	// Copied from net/http/pprof/pprof.go
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, httpServeHook(server.ListenAndServe))
	life.RegisterStop(lifecycle.StopMonitoringAPI, lifecycle.HookFunc(server.Shutdown))
}

// startReadyChecker returns function which returns an error resulting from ready checks periodically.
func startReadyChecker(ctx context.Context, tcpNode host.Host, eth2Cl eth2client.NodeSyncingProvider, peerIDs []peer.ID,
	clock clockwork.Clock, pubkeys []core.PubKey, seenPubkeys chan core.PubKey,
) func() error {
	const minNotConnected = 6 // Require 6 rounds (1min) of too few connected
	var (
		mu                 sync.Mutex
		readyErr           = errReadyUninitialised
		notConnectedRounds = minNotConnected // Start as not connected.
	)
	go func() {
		ticker := clock.NewTicker(10 * time.Second)
		epochTicker := clock.NewTicker(32 * 12 * time.Second) // 32 slots * 12 second slot time
		previous := make(map[core.PubKey]bool)

		// newCurrent returns a new current map, populated with all the pubkeys.
		newCurrent := func() map[core.PubKey]bool {
			current := make(map[core.PubKey]bool)
			for _, pubkey := range pubkeys {
				current[pubkey] = true
			}

			return current
		}

		// Initialise current.
		current := newCurrent()

		for {
			select {
			case <-ctx.Done():
				return
			case <-epochTicker.Chan():
				// Copy current to previous and clear current.
				previous, current = current, newCurrent()
			case <-ticker.Chan():
				if quorumPeersConnected(peerIDs, tcpNode) {
					notConnectedRounds = 0
				} else {
					notConnectedRounds++
				}

				syncing, err := beaconNodeSyncing(ctx, eth2Cl)
				//nolint:nestif
				if err != nil {
					err = errReadyBeaconNodeDown
					readyzGauge.Set(readyzBeaconNodeDown)
				} else if syncing {
					err = errReadyBeaconNodeSyncing
					readyzGauge.Set(readyzBeaconNodeSyncing)
				} else if notConnectedRounds >= minNotConnected {
					err = errReadyInsufficientPeers
					readyzGauge.Set(readyzInsufficientPeers)
				} else if len(previous) == len(pubkeys) {
					err = errReadyVCNotConfigured
					readyzGauge.Set(readyzVCNotConfigured)
				} else if len(previous) > 0 {
					err = errReadyVCMissingVals
					readyzGauge.Set(readyzVCMissingValidators)
				} else {
					readyzGauge.Set(readyzReady)
				}

				mu.Lock()
				readyErr = err
				mu.Unlock()
			case pubkey := <-seenPubkeys:
				// Delete pubkey if called by a VC.
				delete(current, pubkey)
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

// peerCounter populates the peerCountGauge with the beacon node peer count.
func peerCounter(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	ticker := clock.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.Chan():
				resp, err := beaconNodePeerCount(ctx, eth2Cl)
				if err != nil {
					log.Error(ctx, "Failed to get beacon node peer count", err)
				}
				peerCountGauge.Set(float64(resp))
			}
		}
	}()
}

// beaconNodePeerCount returns the number of connected peers of the beacon node.
func beaconNodePeerCount(ctx context.Context, eth2Cl eth2wrap.Client) (int, error) {
	peerCount, err := eth2Cl.NodePeerCount(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get beacon node peer count")
	}

	return peerCount.Connected, nil
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
