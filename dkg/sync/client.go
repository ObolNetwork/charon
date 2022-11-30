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
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

// NewClient returns a new Client instance.
func NewClient(tcpNode host.Host, peer peer.ID, hashSig []byte) *Client {
	return &Client{
		tcpNode:   tcpNode,
		peer:      peer,
		hashSig:   hashSig,
		shutdown:  make(chan struct{}),
		done:      make(chan struct{}),
		reconnect: true,
	}
}

// Client is the client side of the sync protocol. It retries establishing a connection to a sync server,
// it sends period pings (including definition hash signatures),
// supports reestablishing on relay circuit recycling, and supports soft shutdown.
type Client struct {
	// Mutable state
	mu        sync.Mutex
	connected bool
	reconnect bool
	shutdown  chan struct{}
	done      chan struct{}

	// Immutable state
	hashSig []byte
	tcpNode host.Host
	peer    peer.ID
}

// Run blocks while running the client-side sync protocol. It returns an error if the context is closed
// or if an established connection is dropped. It returns nil after successful Shutdown.
func (c *Client) Run(ctx context.Context) error {
	defer close(c.done)

	ctx = log.WithCtx(ctx, z.Str("peer", p2p.PeerName(c.peer)))

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		stream, err := c.connect(ctx)
		if err != nil {
			return err
		}

		c.setConnected()

		relayBroke, connBroke, err := c.sendMsgs(ctx, stream)
		if relayBroke || (c.reconnect && connBroke) {
			continue
		} else if err != nil {
			return err
		}

		return nil
	}
}

// IsConnected blocks until the connection with the server has been established or returns a context error.
func (c *Client) IsConnected(ctx context.Context) error {
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if c.isConnected() {
				return nil
			}
		}
	}
}

// Shutdown triggers the Run goroutine to shut down gracefully and returns nil after it has returned.
// It should be called after IsConnected and may only be called once.
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

// isConnected returns the shared connected state.
func (c *Client) isConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.connected
}

// sendMsgs sends period sync protocol messages on the stream until error or shutdown.
func (c *Client) sendMsgs(ctx context.Context, stream network.Stream) (relayBroke bool, connBroke bool, err error) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	defer c.clearConnected()

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
		} else if resp.Error == errInvalidSig {
			return false, false, errors.New("mismatching cluster definition hash with peer")
		} else if resp.Error != "" {
			return false, false, errors.New("peer responded with error", z.Str("error_message", resp.Error))
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
	for {
		s, err := c.tcpNode.NewStream(network.WithUseTransient(ctx, "sync"), c.peer, protocolID)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		} else if err != nil {
			if c.reconnect {
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
