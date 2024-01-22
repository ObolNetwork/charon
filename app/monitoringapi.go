// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/health"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
)

// bnFarBehindSlots is the no of slots that is considered to be too far behind the current beacon chain head.
// Currently, it is set to 10 epochs (10 * 32 = 320 slots).
const bnFarBehindSlots = 320

var (
	errReadyUninitialised       = errors.New("ready check uninitialised")
	errReadyInsufficientPeers   = errors.New("quorum peers not connected")
	errReadyBeaconNodeDown      = errors.New("beacon node down")
	errReadyBeaconNodeFarBehind = errors.New("beacon node far behind")
	errReadyBeaconNodeSyncing   = errors.New("beacon node not synced")
	errReadyBeaconNodeZeroPeers = errors.New("beacon node has zero peers")
	errReadyVCNotConnected      = errors.New("vc not connected")
	errReadyVCMissingVals       = errors.New("vc missing validators")
)

// wireMonitoringAPI constructs the monitoring API and registers it with the life cycle manager.
// It serves prometheus metrics, pprof profiling and the runtime enr.
func wireMonitoringAPI(ctx context.Context, life *lifecycle.Manager, promAddr, debugAddr string,
	tcpNode host.Host, eth2Cl eth2wrap.Client,
	peerIDs []peer.ID, registry *prometheus.Registry, qbftDebug http.Handler,
	pubkeys []core.PubKey, seenPubkeys <-chan core.PubKey, vapiCalls <-chan struct{},
) {
	beaconNodeVersionMetric(ctx, eth2Cl, clockwork.NewRealClock())

	mux := http.NewServeMux()

	// Serve prometheus metrics wrapped with cluster and node identifiers.
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	))

	// Serve monitoring endpoints
	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, "ok")
	}))

	readyErrFunc := startReadyChecker(ctx, tcpNode, eth2Cl, peerIDs, clockwork.NewRealClock(),
		pubkeys, seenPubkeys, vapiCalls)

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		readyErr := readyErrFunc()
		if readyErr != nil {
			writeResponse(w, http.StatusInternalServerError, readyErr.Error())
			return
		}

		writeResponse(w, http.StatusOK, "ok")
	})

	server := &http.Server{
		Addr:              promAddr,
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}

	// Create and start health checker.
	checker := health.NewChecker(health.Metadata{
		NumValidators: len(pubkeys),
		NumPeers:      len(peerIDs),
		QuorumPeers:   cluster.Threshold(len(peerIDs)),
	}, registry)

	if debugAddr != "" {
		debugMux := http.NewServeMux()

		// Serve sniffed qbft instances messages in gzipped protobuf format.
		debugMux.Handle("/debug/qbft", qbftDebug)

		// Copied from net/http/pprof/pprof.go
		debugMux.HandleFunc("/debug/pprof/", pprof.Index)
		debugMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		debugMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		debugServer := &http.Server{
			Addr:              debugAddr,
			Handler:           debugMux,
			ReadHeaderTimeout: time.Second,
		}

		life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartDebugAPI, httpServeHook(debugServer.ListenAndServe))
		life.RegisterStop(lifecycle.StopDebugAPI, lifecycle.HookFunc(debugServer.Shutdown))
	}

	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, httpServeHook(server.ListenAndServe))
	life.RegisterStart(lifecycle.AsyncBackground, lifecycle.StartMonitoringAPI, lifecycle.HookFuncCtx(checker.Run))
	life.RegisterStop(lifecycle.StopMonitoringAPI, lifecycle.HookFunc(server.Shutdown))
}

// startReadyChecker returns function which returns an error resulting from ready checks periodically.
func startReadyChecker(ctx context.Context, tcpNode host.Host, eth2Cl eth2wrap.Client, peerIDs []peer.ID,
	clock clockwork.Clock, pubkeys []core.PubKey, seenPubkeys <-chan core.PubKey, vapiCalls <-chan struct{},
) func() error {
	const minNotConnected = 6 // Require 6 rounds (1min) of too few connected
	var (
		mu                 sync.Mutex
		readyErr           = errReadyUninitialised
		notConnectedRounds = minNotConnected // Start as not connected.
	)
	go func() {
		ticker := clock.NewTicker(10 * time.Second)
		peerCountTicker := clock.NewTicker(1 * time.Minute)
		epochTicker := clock.NewTicker(32 * 12 * time.Second) // 32 slots * 12 second slot time
		var bnPeerCount *int                                  // Beacon node peer count value which is queried every minute
		currVAPICount := 0
		prevVAPICount := 1 // Assume connected.
		currPKs := make(map[core.PubKey]bool)
		prevPKs := make(map[core.PubKey]bool)
		for _, pubkey := range pubkeys { // Assume all validators seen.
			prevPKs[pubkey] = true
		}

		// beaconNodePeerCount queries beacon node peer count and sets the peer count gauge if err is nil.
		beaconNodePeerCount := func() {
			peerCount, err := eth2Cl.NodePeerCount(ctx)
			if err != nil {
				log.Warn(ctx, "Failed to get beacon node peer count", err)
				return
			}
			if bnPeerCount == nil {
				bnPeerCount = new(int)
			}
			bnPeerCount = &peerCount
			beaconNodePeerCountGauge.Set(float64(peerCount))
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-epochTicker.Chan():
				// Copy current to previous and clear current.
				prevPKs, currPKs = currPKs, make(map[core.PubKey]bool)
				prevVAPICount, currVAPICount = currVAPICount, 0
			case <-peerCountTicker.Chan():
				beaconNodePeerCount()
			case <-ticker.Chan():
				if quorumPeersConnected(peerIDs, tcpNode) {
					notConnectedRounds = 0
				} else {
					notConnectedRounds++
				}

				syncing, syncDistance, err := beaconNodeSyncing(ctx, eth2Cl)
				if err != nil {
					err = errReadyBeaconNodeDown
					readyzGauge.Set(readyzBeaconNodeDown)
				} else if syncing {
					err = errReadyBeaconNodeSyncing
					readyzGauge.Set(readyzBeaconNodeSyncing)
				} else if bnPeerCount != nil && *bnPeerCount == 0 {
					err = errReadyBeaconNodeZeroPeers
					readyzGauge.Set(readyzBeaconNodeZeroPeers)
				} else if syncDistance > bnFarBehindSlots {
					err = errReadyBeaconNodeFarBehind
					readyzGauge.Set(readyzBeaconNodeFarBehind)
				} else if notConnectedRounds >= minNotConnected {
					err = errReadyInsufficientPeers
					readyzGauge.Set(readyzInsufficientPeers)
				} else if prevVAPICount == 0 {
					err = errReadyVCNotConnected
					readyzGauge.Set(readyzVCNotConnected)
				} else if len(prevPKs) < len(pubkeys) {
					err = errReadyVCMissingVals
					readyzGauge.Set(readyzVCMissingValidators)
				} else {
					readyzGauge.Set(readyzReady)
				}

				mu.Lock()
				readyErr = err
				mu.Unlock()
			case pubkey := <-seenPubkeys:
				currPKs[pubkey] = true
			case <-vapiCalls:
				currVAPICount++
			}
		}
	}()

	return func() error {
		mu.Lock()
		defer mu.Unlock()

		return readyErr
	}
}

// beaconNodeSyncing returns true if the beacon node is still syncing. It also returns the sync distance, ie, the distance
// between the node's highest synced slot and the head slot.
func beaconNodeSyncing(ctx context.Context, eth2Cl eth2client.NodeSyncingProvider) (bool, eth2p0.Slot, error) {
	eth2Resp, err := eth2Cl.NodeSyncing(ctx, &eth2api.NodeSyncingOpts{})
	if err != nil {
		return false, 0, err
	}

	return eth2Resp.Data.IsSyncing, eth2Resp.Data.SyncDistance, nil
}

// beaconNodeVersionMetric sets the beacon node version gauge.
func beaconNodeVersionMetric(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) {
	nodeVersionTicker := clock.NewTicker(10 * time.Minute)

	setNodeVersion := func() {
		eth2Resp, err := eth2Cl.NodeVersion(ctx, &eth2api.NodeVersionOpts{})
		if err != nil {
			log.Error(ctx, "Failed to get beacon node version", err)
			return
		}
		version := eth2Resp.Data

		beaconNodeVersionGauge.Reset()
		beaconNodeVersionGauge.WithLabelValues(version).Set(1)
	}

	go func() {
		onStartup := make(chan struct{}, 1)
		onStartup <- struct{}{}

		for {
			select {
			case <-onStartup:
				setNodeVersion()
			case <-nodeVersionTicker.Chan():
				setNodeVersion()
			case <-ctx.Done():
				return
			}
		}
	}()
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
