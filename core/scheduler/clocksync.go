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

package scheduler

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/jonboulle/clockwork"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const (
	maxOffset   = time.Second * 6 // Half a slot
	offsetCount = 10
)

// newClockSyncer returns a function that returns the current median beacon node clock sync offset.
// The clock sync offset is the duration we need to add to our clock to sync with the beacon node's clock.
// TODO(corver): Improve accuracy by subtracting half ping rtt.
func newClockSyncer(ctx context.Context, eventsProvider eth2client.EventsProvider, clock clockwork.Clock,
	genesis time.Time, slotDuration time.Duration,
) (func() time.Duration, error) {
	var (
		mu           sync.Mutex
		medianOffset time.Duration
		offsets      []time.Duration
	)

	// Subscribe to head events to sync beacon node clock
	err := eventsProvider.Events(ctx, []string{"head"}, func(event *eth2v1.Event) {
		if event.Topic != "head" {
			return
		}
		head, ok := event.Data.(*eth2v1.HeadEvent)
		if !ok {
			log.Error(ctx, "Invalid head event data type", nil, z.Str("type", fmt.Sprintf("%T", head)))
			return
		}

		startTime := genesis.Add(time.Duration(head.Slot) * slotDuration)
		newOffset := clock.Since(startTime)

		offsets = append(offsets, newOffset)
		if len(offsets) < offsetCount {
			return
		}

		offsets = offsets[len(offsets)-offsetCount:] // Trim buffer to max offsetCount items.

		clone := append([]time.Duration(nil), offsets...)
		sort.Slice(clone, func(i, j int) bool {
			return clone[i] < clone[j]
		})

		median := clone[len(clone)/2]
		syncMedianGauge.Set(medianOffset.Seconds())
		if median < -maxOffset || median > maxOffset {
			// This will spam logs, but probably ok since this is bad.
			log.Warn(ctx, "Ignoring too big beacon node clock sync offset", nil,
				z.Any("offset", median), z.U64("slot", uint64(head.Slot)))
			return
		}

		mu.Lock()
		medianOffset = median
		mu.Unlock()
	})
	if err != nil {
		return nil, err
	}

	return func() time.Duration {
		mu.Lock()
		defer mu.Unlock()

		return medianOffset
	}, nil
}
