// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package leadercast

import (
	"context"
	"sync"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/types"
)

// New returns a new leader cast consensus implementation
// for the node at index in the total cluster.
func New(transport Transport, index, total int) *LeaderCast {
	return &LeaderCast{
		total:     total,
		index:     index,
		transport: transport,
		buffers:   make(map[types.Duty]chan []byte),
		stop:      func() {},
	}
}

// LeaderCast provides a naive consensus implementation.
// Given a cluster with a static ordered set of nodes, the leader
// selected for each duty broadcasts its proposed data. All other nodes
// await and resolve the leader's data.
//
// Note this is neither HA nor BFT.
type LeaderCast struct {
	total     int // total number of nodes in the cluster
	index     int // index of this node in the cluster
	transport Transport

	mu      sync.Mutex
	buffers map[types.Duty]chan []byte
	stop    context.CancelFunc
}

func (l *LeaderCast) Start() error {
	ctx := log.WithTopic(context.Background(), "leadercast")
	ctx, l.stop = context.WithCancel(ctx)

	for {
		source, duty, data, err := l.transport.AwaitNext(ctx)
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil //nolint:nilerr
		} else if err != nil {
			log.Error(ctx, "await next leader duty", err)
			continue
		}

		if !isLeader(source, l.total, duty) {
			log.Warn(ctx, "received duty from non-leader", z.Int("peer", source))
			continue
		}

		log.Debug(ctx, "received duty from leader", z.Int("peer", source), z.Any("duty", duty))

		l.getBuffer(duty) <- data
		// TODO(corver): Trim channels that are never resolved.
	}
}

// getBuffer returns the channel to buffer the duty data.
func (l *LeaderCast) getBuffer(duty types.Duty) chan []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch, ok := l.buffers[duty]
	if !ok {
		ch = make(chan []byte, 1)
		l.buffers[duty] = ch
	}

	return ch
}

func (l *LeaderCast) Stop() {
	l.stop()
}

func (l *LeaderCast) ResolveDuty(ctx context.Context, duty types.Duty, data []byte) ([]byte, error) {
	if isLeader(l.index, l.total, duty) {
		if err := l.transport.Broadcast(ctx, l.index, duty, data); err != nil {
			return nil, err
		}

		return data, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-l.getBuffer(duty):
		l.mu.Lock()
		delete(l.buffers, duty)
		l.mu.Unlock()

		return data, nil
	}
}

// isLeader is a deterministic LeaderCast election function that returns true if the instance at index (of total)
// is the LeaderCast for the given duty.
func isLeader(index, total int, d types.Duty) bool {
	mod := (d.Slot + int(d.Type)) % total

	return mod == index
}
