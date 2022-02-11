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
	"github.com/obolnetwork/charon/consensus"
)

// NewLeaderCast returns a new leader cast consensus implementation
// for the node at index in the total cluster.
func NewLeaderCast(transport Transport, index, total int) *LeaderCast {
	return &LeaderCast{
		total:     total,
		index:     index,
		transport: transport,
		cond:      sync.Cond{L: new(sync.Mutex)},
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

	cond   sync.Cond
	duties []dutyTuple
	stop   context.CancelFunc
}

func (l *LeaderCast) Start() error {
	ctx := log.WithTopic(context.Background(), "leadercast")
	ctx, l.stop = context.WithCancel(ctx)

	for {
		source, d, data, err := l.transport.AwaitNext(ctx)
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil //nolint:nilerr
		} else if err != nil {
			log.Error(ctx, "await next leader duty", err)
			continue
		}

		if !isLeader(source, l.total, d) {
			log.Warn(ctx, "received duty from non-leader", z.Int("peer", source))
			continue
		}

		log.Debug(ctx, "received duty from leader", z.Int("peer", source), z.Any("duty", d))

		l.cond.L.Lock()
		l.duties = append(l.duties, dutyTuple{
			Duty: d,
			Data: data,
		})
		l.cond.L.Unlock()
		l.cond.Signal()
		// TODO(corver): Trim old resolved duties.
	} //nolint:wsl
}

func (l *LeaderCast) Stop() {
	l.stop()
}

func (l *LeaderCast) ResolveDuty(ctx context.Context, d consensus.Duty, data []byte) ([]byte, error) {
	if isLeader(l.index, l.total, d) {
		if err := l.transport.Broadcast(ctx, l.index, d, data); err != nil {
			return nil, err
		}

		return data, nil
	}

	// Wait for leader's duty using conditional
	// lock that is signalled when duties are received.
	//
	// Wrap this in async for responsive timeouts since waiting
	// on condition doesn't support context.
	var resp []byte

	err := async(ctx, func() error {
		l.cond.L.Lock()
		defer l.cond.L.Unlock()

		for {
			if ctx.Err() != nil { // Timed out
				return ctx.Err()
			}

			for _, t := range l.duties {
				if t.Duty == d {
					resp = t.Data
					return nil
				}
			}

			// Duty not received yet, give up the lock and wait for a signal.
			l.cond.Wait()
			// Note that when continuing here, we have the lock again.
		}
	})

	return resp, err
}

// isLeader is a deterministic LeaderCast election function that returns true if the ith instance (of total instances)
// is the LeaderCast for the given duty.
func isLeader(ith, total int, d consensus.Duty) bool {
	mod := (d.Slot + int(d.Type)) % total
	return mod == ith
}

type dutyTuple struct {
	Duty consensus.Duty
	Data []byte
}

// async calls the fn asynchronously returning either its response or
// a context cancel error, whichever happens first.
func async(ctx context.Context, fn func() error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan error, 1)

	go func() {
		ch <- fn()
	}()

	go func() {
		<-ctx.Done()
		ch <- ctx.Err()
	}()

	return <-ch
}
