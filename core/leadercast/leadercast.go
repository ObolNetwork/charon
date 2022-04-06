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

package leadercast

import (
	"context"

	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// New returns a new leader cast consensus implementation
// for the peer at index of a total number of peers.
func New(transport Transport, peerIdx, peers int) *LeaderCast {
	return &LeaderCast{
		peers:     peers,
		peerIdx:   peerIdx,
		transport: transport,
	}
}

// LeaderCast provides a naive consensus implementation.
// Given a cluster with a static ordered set of nodes, the leader
// selected for each duty broadcasts its proposed data. All other nodes
// await and resolve the leader's data.
//
// Note this is neither HA nor BFT.
type LeaderCast struct {
	peers     int // total number of peers in the cluster
	peerIdx   int // index of this peers in the cluster
	transport Transport

	subs []func(context.Context, core.Duty, core.UnsignedDataSet) error
}

func (l *LeaderCast) Run(ctx context.Context) error {
	ctx = log.WithTopic(ctx, "lcast")

	for {
		source, duty, data, err := l.transport.AwaitNext(ctx)
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		} else if err != nil {
			log.Error(ctx, "await next leader duty", err)
			continue
		}

		if !isLeader(source, l.peers, duty) {
			log.Warn(ctx, "received duty from non-leader", z.Int("peer", source))
			continue
		}

		log.Debug(ctx, "received duty from leader", z.Int("peer", source), z.Any("duty", duty))

		var span trace.Span
		ctx, span = core.StartDutyTrace(ctx, duty, "core/leadercast.Handle")

		for _, sub := range l.subs {
			if err := sub(ctx, duty, data); err != nil {
				log.Error(ctx, "subscriber error", err)
				continue
			}
		}

		span.End()
	}
}

// Subscribe registers a callback for unsigned duty data proposals from leaders.
// Note this function is not thread safe, it should be called *before* Run or Propose.
func (l *LeaderCast) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
	l.subs = append(l.subs, fn)
}

// Propose proposes an unsigned duty data object for consensus. If this peer is the leader, then it is
// broadcasted to all peers (including self), else the proposal is ignored.
func (l *LeaderCast) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	if !isLeader(l.peerIdx, l.peers, duty) {
		return nil
	}

	err := l.transport.Broadcast(ctx, l.peerIdx, duty, data)
	if err != nil {
		return err
	}

	for _, sub := range l.subs {
		if err := sub(ctx, duty, data); err != nil {
			return err
		}
	}

	return nil
}

// isLeader is a deterministic leader election function that returns true if the peer at index (of total)
// is the leader for the given duty.
func isLeader(peerIdx, peers int, d core.Duty) bool {
	mod := (int(d.Slot) + int(d.Type)) % peers

	return mod == peerIdx
}
