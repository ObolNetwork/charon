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
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestClockSync(t *testing.T) {
	clock := clockwork.NewFakeClock()
	slotDuration := time.Second
	provider := &testEventsProvider{t: t}
	syncOffset, err := newClockSyncer(context.Background(), provider, clock, clock.Now(), slotDuration)
	require.NoError(t, err)

	require.Zero(t, syncOffset())

	const smallOffset = maxOffset / 10

	clock.Advance(smallOffset)

	var slot int

	// Offset is zero until min 10 events
	for i := 0; i < offsetCount-1; i++ {
		clock.Advance(slotDuration)
		slot++
		provider.Push(slot)
		require.Zero(t, syncOffset())
	}

	clock.Advance(slotDuration)
	slot++
	provider.Push(slot)

	require.Equal(t, smallOffset, syncOffset())

	// Increase offset
	clock.Advance(smallOffset)

	// First 4 slots will still be previous median
	for i := 0; i < (offsetCount/2 - 1); i++ {
		clock.Advance(slotDuration)
		slot++
		provider.Push(slot)
		require.Equal(t, smallOffset, syncOffset())
	}

	// Next slot has new expected offset
	clock.Advance(slotDuration)
	slot++
	provider.Push(slot)
	require.Equal(t, 2*smallOffset, syncOffset())

	// Increase offset to more than max
	clock.Advance(maxOffset)

	// Median never updated since new offset too big.
	for i := 0; i < offsetCount; i++ {
		clock.Advance(slotDuration)
		slot++
		provider.Push(slot)
		require.Equal(t, 2*smallOffset, syncOffset())
	}
}

type testEventsProvider struct {
	t       *testing.T
	handler eth2client.EventHandlerFunc
}

func (p *testEventsProvider) Events(_ context.Context, topics []string, handler eth2client.EventHandlerFunc) error {
	require.Equal(p.t, []string{"head"}, topics)
	p.handler = handler

	return nil
}

func (p *testEventsProvider) Push(slot int) {
	p.handler(&eth2v1.Event{
		Topic: "head",
		Data:  &eth2v1.HeadEvent{Slot: eth2p0.Slot(slot)},
	})
}
