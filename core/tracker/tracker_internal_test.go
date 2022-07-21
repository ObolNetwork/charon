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

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestTracker1(t *testing.T) {
	duty, defSet, pubkey, unsignedDataSet, parSignedDataSet := setupData1(t)

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner1{
			deadlineChan: make(chan core.Duty),
		}

		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, component, "consensus")
			cancel()
		}

		tr := New(deadliner)
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			require.NoError(t, tr.SchedulerEvent(ctx, duty, defSet))
			require.NoError(t, tr.FetcherEvent(ctx, duty, unsignedDataSet))

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- duty
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})

	t.Run("Success", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner1{
			deadlineChan: make(chan core.Duty),
		}

		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, "sigAgg", component)
			cancel()
		}

		tr := New(deadliner)
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			require.NoError(t, tr.SchedulerEvent(ctx, duty, defSet))
			require.NoError(t, tr.FetcherEvent(ctx, duty, unsignedDataSet))
			require.NoError(t, tr.ConsensusEvent(ctx, duty, unsignedDataSet))
			require.NoError(t, tr.ValidatorAPIEvent(ctx, duty, parSignedDataSet))
			require.NoError(t, tr.ParSigDBInternalEvent(ctx, duty, parSignedDataSet))
			require.NoError(t, tr.ParSigExEvent(ctx, duty, parSignedDataSet))
			require.NoError(t, tr.ParSigDBThresholdEvent(ctx, duty, pubkey, nil))
			require.NoError(t, tr.SigAggEvent(ctx, duty, pubkey, nil))

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- duty
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner1 struct {
	deadlineChan chan core.Duty
}

func (testDeadliner1) Add(core.Duty) {}

func (t testDeadliner1) C() <-chan core.Duty {
	return t.deadlineChan
}

// setupData returns the data required to test tracker.
func setupData1(t *testing.T) (core.Duty, core.DutyDefinitionSet, core.PubKey, core.UnsignedDataSet, core.ParSignedDataSet) {
	t.Helper()

	const (
		slot    = 1
		vIdxA   = 2
		vIdxB   = 3
		notZero = 99 // Validation require non-zero values
	)

	pubkey := testutil.RandomCorePubKey(t)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: pubkey,
		vIdxB: pubkey,
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

	unsignedDataSet := make(core.UnsignedDataSet)
	for pubkey := range defSet {
		unsignedDataSet[pubkey] = testutil.RandomCoreAttestationData(t)
	}

	parSignedDataSet := make(core.ParSignedDataSet)
	for pubkey := range defSet {
		parSignedDataSet[pubkey] = core.ParSignedData{
			SignedData: nil,
			ShareIdx:   0,
		}
	}

	return duty, defSet, pubkey, unsignedDataSet, parSignedDataSet
}
