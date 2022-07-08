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

package tracker

import (
	"context"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/fetcher"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestTracker_FetcherEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	deadlineFunc, err := core.NewDutyDeadlineFunc(ctx, bmock)
	require.NoError(t, err)

	duty, defSet := fetcherHelper(t)

	// Run tracker in a new goroutine.
	tr := NewForT(deadlineFunc, len(defSet))
	go func() {
		err := tr.Run(ctx)
		if err != nil {
			log.Error(ctx, "Failed to run tracker", err)
			cancel()
		}
	}()

	// Run fetch and subscribe it to tracker.
	fetch, err := fetcher.New(bmock)
	require.NoError(t, err)

	fetch.Subscribe(tr.AwaitFetcherEvent)
	err = fetch.Fetch(ctx, duty, defSet)
	require.NoError(t, err)

	for i := 0; i < len(defSet); i++ {
		e := <-tr.testChan
		require.Equal(t, e.duty, duty)

		_, ok := defSet[e.pubkey]
		require.True(t, ok)
		require.Equal(t, e.component, Fetcher)
	}
}

func fetcherHelper(t *testing.T) (core.Duty, core.DutyDefinitionSet) {
	t.Helper()

	const (
		slot    = 1
		vIdxA   = 2
		vIdxB   = 3
		notZero = 99 // Validation require non-zero values
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	dutyA := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxA,
		CommitteeIndex:   vIdxA,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}

	dutyB := eth2v1.AttesterDuty{
		Slot:             slot,
		ValidatorIndex:   vIdxB,
		CommitteeIndex:   vIdxB,
		CommitteeLength:  notZero,
		CommitteesAtSlot: notZero,
	}

	defSet := core.DutyDefinitionSet{
		pubkeysByIdx[vIdxA]: core.NewAttesterDefinition(&dutyA),
		pubkeysByIdx[vIdxB]: core.NewAttesterDefinition(&dutyB),
	}

	duty := core.Duty{Type: core.DutyAttester, Slot: slot}

	return duty, defSet
}
