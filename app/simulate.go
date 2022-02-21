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

package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/types"
)

// newDutySimulator returns a start and stop function that
// simulates consensus duty resolution with periodic mock data.
func newDutySimulator(cons cluster.Consensus,
	period time.Duration, callback func(types.Duty, []byte),
) (func() error, context.CancelFunc) {

	ctx := log.WithTopic(context.Background(), "sim-duty")
	ctx, cancel := context.WithCancel(ctx)

	if period == 0 {
		period = time.Second * 5
	}

	slotZero := time.Now().Truncate(time.Hour * 24)

	// slotFromTime returns a deterministic slot from a timestamp.
	slotFromTime := func(ts time.Time) int {
		return int(ts.Sub(slotZero) / period)
	}

	// nextSlot returns a timer channel for the start of the next slot.
	nextSlot := func() <-chan time.Time {
		now := time.Now()
		next := now.Truncate(period).Add(period)

		return time.NewTimer(next.Sub(now)).C
	}

	return func() error {
			for {
				select {
				case ts := <-nextSlot():
					// Do not block resolving duty, just kick it off.
					go func() {
						duty := types.Duty{
							Slot: slotFromTime(ts),
							Type: types.DutyAttester,
						}

						err := simulateDuty(ctx, cons, duty, callback)
						if err != nil {
							log.Error(ctx, "Simulate duty error", err, z.Int("slot", duty.Slot))
						}
					}()
				case <-ctx.Done():
					return nil
				}
			}
		}, func() {
			cancel()
		}
}

func simulateDuty(ctx context.Context, cons cluster.Consensus, duty types.Duty,
	callback func(types.Duty, []byte),
) error {

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	data := make([]byte, 2)
	_, _ = rand.Read(data)
	data = []byte(fmt.Sprintf("att:%x", data))

	data, err := cons.ResolveDuty(ctx, duty, data)
	if errors.Is(err, context.Canceled) {
		return nil
	} else if err != nil {
		return err
	}

	log.Info(ctx, "Resolved duty", z.Any("duty", duty), z.Str("data", string(data)))

	if callback != nil {
		callback(duty, data)
	}

	return nil
}
