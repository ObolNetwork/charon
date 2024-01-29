// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// TestPingConfig overrides ping config for testing.
type TestPingConfig struct {
	// Disable disables pinging.
	Disable bool
	// Callback is called on successful pings.
	Callback func(peer.ID, host.Host)
	// MaxBackoff overrides default max backoff.
	MaxBackoff time.Duration
}

// NewPingService returns a start function of a p2p ping service that pings all peers every second
// and collects metrics.
func NewPingService(h host.Host, peers []peer.ID, conf TestPingConfig) lifecycle.HookFuncCtx {
	if conf.Disable {
		return func(ctx context.Context) {}
	}

	maxBackoff := time.Second * 30 // Sweet spot between not spamming, but snappy recovery.
	if conf.MaxBackoff != 0 {
		maxBackoff = conf.MaxBackoff
	}

	svc := ping.NewPingService(h)

	return func(ctx context.Context) {
		ctx = log.WithTopic(ctx, "ping")

		for _, p := range peers {
			if p == h.ID() {
				// Do not ping self
				continue
			}

			go func(p peer.ID) {
				callback := conf.Callback
				if callback == nil {
					// Use delaying callback for periodic 1s pings in production (no test config callback).
					callback = newPingDelayCallback()
				}

				pingPeer(ctx, svc, p, callback, maxBackoff)
			}(p)
		}
	}
}

// pingPeer starts (and restarts) a long-lived ping service stream, pinging the peer every second until some error.
// It returns when the context is cancelled.
func pingPeer(ctx context.Context, svc *ping.PingService, p peer.ID, callback func(peer.ID, host.Host),
	maxBackoff time.Duration,
) {
	backoff := expbackoff.New(ctx, expbackoff.WithMaxDelay(maxBackoff)) // Start quick, then slow down
	logFunc := newPingLogger(svc.Host, p)
	for ctx.Err() == nil {
		pingPeerOnce(ctx, svc, p, logFunc, callback)
		backoff()
	}
}

// pingPeerOnce starts a long lived ping connection with the peer and returns on first error.
func pingPeerOnce(ctx context.Context, svc *ping.PingService, p peer.ID,
	logFunc func(context.Context, ping.Result), callback func(peer.ID, host.Host),
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// newPingChan creates a new stream and returns the ping result channel to listen for results
	// and a close function to close the stream.
	// Note: The only way to close a stream opened by ping service is to cancel the context.
	newPingChan := func() (<-chan ping.Result, func()) {
		pingCtx, pingCancel := context.WithCancel(ctx)

		return svc.Ping(pingCtx, p), pingCancel
	}

	for {
		// Create new stream to use the "best" connection for next ping.
		pingChan, pingCloseFunc := newPingChan()

		select {
		case <-ctx.Done():
			return
		case result := <-pingChan: // Only ping once to always use "best" connection.
			if IsRelayError(result.Error) || errors.Is(result.Error, context.Canceled) {
				// Just exit if relay error or context cancelled.
				return
			}

			logFunc(ctx, result)

			if result.Error != nil {
				incPingError(p)
				// Manually exit on first error since some error (like resource scoped closed)
				// result in ping just hanging.
				return
			}

			observePing(p, result.RTT)
			callback(p, svc.Host)
		}

		// Signal ping service to close the existing stream to avoid having orphaned streams.
		pingCloseFunc()
	}
}

// IsRelayError returns true if the error is due to temporary relay circuit recycling.
func IsRelayError(err error) bool {
	return errors.Is(err, network.ErrReset) ||
		errors.Is(err, network.ErrResourceScopeClosed)
}

// newPingLogger returns stateful logging function that logs "real" dial errors when they change or every 10min.
// This is the main logger of "why are we not connected to peer X".
func newPingLogger(tcpNode host.Host, p peer.ID) func(context.Context, ping.Result) {
	var (
		prevMsgs         = make(map[string]string)
		prevResolvedMsgs = make(map[string]string)
		prevSuccess      bool
		clearedAt        = time.Now()
		clearPeriod      = time.Minute * 10 // Log same msgs every 10min
	)

	sameMsgs := func(msgs map[string]string) bool {
		return fmt.Sprint(msgs) == fmt.Sprint(prevMsgs) || fmt.Sprint(msgs) == fmt.Sprint(prevResolvedMsgs)
	}

	return func(ctx context.Context, result ping.Result) {
		if result.Error == nil && prevSuccess {
			// All still good
			return
		} else if result.Error == nil && !prevSuccess {
			// Reconnected
			log.Info(ctx, "Peer connected", z.Str("peer", PeerName(p)), z.Any("rtt", result.RTT))
			prevSuccess = true

			return
		}

		if time.Since(clearedAt) > clearPeriod {
			prevMsgs = make(map[string]string)
			prevResolvedMsgs = make(map[string]string)
			clearedAt = time.Now()
		}

		msgs, ok := dialErrMsgs(result.Error)
		if !ok { // Unexpected non-dial reason...
			if prevSuccess {
				log.Warn(ctx, "Peer ping failing", nil, z.Str("peer", PeerName(p)), z.Str("error", result.Error.Error()))
			}
			prevSuccess = false

			return
		}

		if !prevSuccess && sameMsgs(msgs) {
			// Still failing for the same reasons, don't log
			return
		}

		prevMsgs = msgs
		prevSuccess = false

		// Log when failing after success or failing for different reasons

		if hasErrDialBackoff(result.Error) {
			msgs = resolveBackoffMsgs(ctx, tcpNode, p) // Best effort resolving of dial backoff errors.
			if len(msgs) == 0 || sameMsgs(msgs) {
				// No more errors, or same messages, ok well...
				return
			}
			prevResolvedMsgs = msgs
		}

		// TODO(corver): Reconsider this logging format
		opts := []z.Field{z.Str("peer", PeerName(p))}
		for addr, msg := range msgs {
			opts = append(opts, z.Str(addr, msg))
		}

		log.Warn(ctx, "Peer not connected", nil, opts...)
	}
}

func resolveBackoffMsgs(ctx context.Context, tcpNode host.Host, p peer.ID) map[string]string {
	net, ok := tcpNode.Network().(*swarm.Swarm)
	if !ok {
		log.Error(ctx, "Not a swarm network", nil)
		return nil
	}

	net.Backoff().Clear(p)

	_, err := net.DialPeer(ctx, p)
	if err == nil {
		// Connected now....
		return nil
	}

	msgs, ok := dialErrMsgs(err)
	if !ok { // Some other error
		log.Warn(ctx, "Peer dial failing", nil, z.Str("peer", PeerName(p)), z.Str("error", err.Error()))
		return nil
	}

	return msgs
}

// newPingDelayCallback returns a delaying ping callback for periodic 1s pings in production.
func newPingDelayCallback() func(peer.ID, host.Host) {
	const period = time.Second
	timestamp := time.Now()

	return func(peer.ID, host.Host) {
		delay := time.Until(timestamp.Add(period))
		if delay > 0 {
			time.Sleep(delay)
		}
		timestamp = time.Now()
	}
}
