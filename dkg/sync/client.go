// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sync

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// WithPeriod sets the period between pings.
func WithPeriod(period time.Duration) func(*Client) {
	return func(c *Client) {
		c.period = period
	}
}

// NewClient returns a new Client instance.
func NewClient(tcpNode host.Host, peer peer.ID, hashSig []byte, version version.SemVer, opts ...func(*Client)) *Client {
	c := &Client{
		tcpNode:   tcpNode,
		peer:      peer,
		hashSig:   hashSig,
		shutdown:  make(chan struct{}),
		done:      make(chan struct{}),
		reconnect: true,
		version:   version,
		period:    100 * time.Millisecond, // Must be at least two times lower than the sync timeout (dkg.go, startSyncProtocol)
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Client is the client side of the sync protocol. It retries establishing a connection to a sync server,
// it sends period pings (including definition hash signatures),
// supports reestablishing on relay circuit recycling, and supports soft shutdown.
type Client struct {
	// Mutable state
	mu        sync.RWMutex
	connected bool
	reconnect bool
	step      int
	shutdown  chan struct{}
	done      chan struct{}

	// Immutable state
	hashSig []byte
	version version.SemVer
	tcpNode host.Host
	peer    peer.ID
	period  time.Duration
}

// Run blocks while running the client-side sync protocol. It tries to reconnect if relay connection is dropped or
// connection is broken while in reconnect state. It returns nil after successful Shutdown.
func (c *Client) Run(ctx context.Context) error {
	defer close(c.done)

	ctx = log.WithCtx(ctx, z.Str("peer", p2p.PeerName(c.peer)))

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		stream, err := c.connect(ctx)
		if err != nil {
			return errors.Wrap(err, "client connect", z.Str("peer", p2p.PeerName(c.peer)))
		}

		c.setConnected()

		relayBroke, connBroke, err := c.sendMsgs(ctx, stream)
		c.clearConnected()
		if relayBroke {
			log.Debug(ctx, "Relay connection dropped, reconnecting")
			continue // Always reconnect on relay circuit recycling.
		} else if connBroke && c.shouldReconnect() {
			log.Info(ctx, "Disconnected from peer")
			continue // Only reconnect for connection breaks in reconnect state.
		} else if err != nil {
			return errors.Wrap(err, "sync client", z.Str("peer", p2p.PeerName(c.peer)))
		}

		return nil
	}
}

// SetStep sets the current step.
func (c *Client) SetStep(step int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.step = step
}

// getStep returns the current step.
func (c *Client) getStep() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.step
}

// IsConnected returns if client is connected to the server or not.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.connected
}

// Shutdown triggers the Run goroutine to shut down gracefully and returns nil after it has returned.
// It should be called after client is connected and may only be called once.
func (c *Client) Shutdown(ctx context.Context) error {
	close(c.shutdown)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return nil
	}
}

// setConnected sets the shared connected state.
func (c *Client) setConnected() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = true
}

// clearConnected clears the shared connected state.
func (c *Client) clearConnected() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
}

// sendMsgs sends period sync protocol messages on the stream until error or shutdown.
func (c *Client) sendMsgs(ctx context.Context, stream network.Stream) (relayBroke bool, connBroke bool, err error) {
	timer := time.NewTicker(c.period)
	defer timer.Stop()

	first := make(chan struct{}, 1)
	first <- struct{}{}

	var shutdown bool

	for {
		select {
		case <-ctx.Done():
			return false, false, ctx.Err()
		case <-c.shutdown:
			shutdown = true
		case <-first:
		case <-timer.C:
		}

		resp, err := c.sendMsg(stream, shutdown)
		if isRelayError(err) {
			return true, false, err // Reconnect on relay errors
		} else if err != nil { // TODO(dhruv): differentiate between connection errors and other errors.
			return false, true, err
		} else if shutdown {
			return false, false, nil
		} else if resp.Error != "" {
			return false, false, errors.New("peer responded with error: " + resp.Error)
		}

		rtt := time.Since(resp.SyncTimestamp.AsTime())
		c.tcpNode.Peerstore().RecordLatency(c.peer, rtt)
	}
}

// sendMsg sends a sync message and returns the response.
func (c *Client) sendMsg(stream network.Stream, shutdown bool) (*pb.MsgSyncResponse, error) {
	msg := &pb.MsgSync{
		Timestamp:     timestamppb.Now(),
		HashSignature: c.hashSig,
		Shutdown:      shutdown,
		Version:       c.version.String(),
		Step:          int64(c.getStep()),
	}

	if err := writeSizedProto(stream, msg); err != nil {
		return nil, err
	}

	resp := new(pb.MsgSyncResponse)
	if err := readSizedProto(stream, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// connect returns an opened libp2p stream/connection, it will retry if instructed.
func (c *Client) connect(ctx context.Context) (network.Stream, error) {
	backoff := expbackoff.New(
		ctx,
		expbackoff.WithFastConfig(),
		expbackoff.WithMaxDelay(1*time.Second),
	)

	for {
		s, err := c.tcpNode.NewStream(network.WithUseTransient(ctx, "sync"), c.peer, protocolID)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		} else if err != nil {
			if c.shouldReconnect() {
				backoff()
				continue
			}

			return nil, errors.Wrap(err, "open connection")
		}

		return s, nil
	}
}

// isRelayError returns true if the error is due to temporary relay circuit recycling.
func isRelayError(err error) bool {
	return errors.Is(err, network.ErrReset) ||
		errors.Is(err, network.ErrResourceScopeClosed)
}

// DisableReconnect disables shared reconnect state.
func (c *Client) DisableReconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reconnect = false
}

// shouldReconnect returns true if clients should re-attempt connecting to peers.
func (c *Client) shouldReconnect() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.reconnect
}
