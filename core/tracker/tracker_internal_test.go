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
	"reflect"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestTrackerFailedDuty(t *testing.T) {
	const slot = 1
	testData, pubkeys := setupData(t, []int{slot})

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner{
			deadlineChan: make(chan core.Duty),
		}

		count := 0
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, component component, msg string) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, consensus, component)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, _ map[int]bool) {}

		go func() {
			for _, td := range testData {
				require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defSet))
				require.NoError(t, tr.FetcherEvent(ctx, td.duty, td.unsignedDataSet))

				// Explicitly mark the current duty as deadlined.
				deadliner.deadlineChan <- td.duty
			}
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})

	t.Run("Success", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner{
			deadlineChan: make(chan core.Duty),
		}

		count := 0
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, component component, msg string) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, sigAgg, component)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			for _, td := range testData {
				require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defSet))
				require.NoError(t, tr.FetcherEvent(ctx, td.duty, td.unsignedDataSet))
				require.NoError(t, tr.ConsensusEvent(ctx, td.duty, td.unsignedDataSet))
				require.NoError(t, tr.ValidatorAPIEvent(ctx, td.duty, td.parSignedDataSet))
				require.NoError(t, tr.ParSigDBInternalEvent(ctx, td.duty, td.parSignedDataSet))
				require.NoError(t, tr.ParSigExEvent(ctx, td.duty, td.parSignedDataSet))
				for _, pubkey := range pubkeys {
					require.NoError(t, tr.ParSigDBThresholdEvent(ctx, td.duty, pubkey, nil))
					require.NoError(t, tr.SigAggEvent(ctx, td.duty, pubkey, nil))
				}

				// Explicitly mark the current duty as deadlined.
				deadliner.deadlineChan <- td.duty
			}
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})
}

func TestTrackerParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	slots := []int{1, 2, 3}
	testData, pubkeys := setupData(t, slots)

	// Assuming a DV with 4 nodes.
	numPeers := 4
	var peers []p2p.Peer
	for i := 0; i < numPeers; i++ {
		peers = append(peers, p2p.Peer{Index: i})
	}

	// Participation set per duty for a cluster.
	expectedParticipationPerDuty := map[core.Duty]map[int]bool{
		testData[0].duty: {
			1: true,
			2: true,
			3: true,
			4: true,
		},
		testData[1].duty: {
			1: true,
			2: true,
			4: true,
		},
		testData[2].duty: {
			1: true,
			2: true,
			4: true,
		},
	}

	// ParSignedDataSet to be sent by ParSigExEvent per duty per peer for all the DVs.
	psigDataPerDutyPerPeer := make(map[core.Duty][]core.ParSignedDataSet)
	for _, td := range testData {
		// ParSignedDataSet for each peer.
		var data []core.ParSignedDataSet
		for _, p := range peers {
			set := make(core.ParSignedDataSet)
			for _, pk := range pubkeys {
				if !expectedParticipationPerDuty[td.duty][p.ShareIdx()] {
					// This peer hasn't participated in this duty for this DV.
					continue
				}

				set[pk] = core.ParSignedData{ShareIdx: p.ShareIdx()}
			}

			data = append(data, set)
		}

		psigDataPerDutyPerPeer[td.duty] = data
	}

	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(deadliner, peers)

	var count int
	var lastParticipation map[int]bool
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[int]bool) {
		require.Equal(t, testData[count].duty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipationPerDuty[testData[count].duty]))

		if count == 2 {
			// For third duty, last Participation should be equal to that of second duty.
			require.Equal(t, expectedParticipationPerDuty[testData[count].duty], lastParticipation)
		} else {
			require.NotEqual(t, expectedParticipationPerDuty[testData[count].duty], lastParticipation)
		}
		count++

		if count == len(testData) {
			// Signal exit to central go routine.
			cancel()
		}

		lastParticipation = actualParticipation
	}

	// Ignore failedDutyReporter part to isolate participation only.
	tr.failedDutyReporter = func(context.Context, core.Duty, bool, component, string) {}

	go func() {
		for _, td := range testData {
			require.NoError(t, tr.ParSigDBInternalEvent(ctx, td.duty, td.parSignedDataSet))
			for _, data := range psigDataPerDutyPerPeer[td.duty] {
				require.NoError(t, tr.ParSigExEvent(ctx, td.duty, data))
			}
			for _, pk := range pubkeys {
				require.NoError(t, tr.ParSigDBThresholdEvent(ctx, td.duty, pk, nil))
				require.NoError(t, tr.SigAggEvent(ctx, td.duty, pk, nil))
			}

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- td.duty
		}
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

// testDeadliner is a mock deadliner implementation.
type testDeadliner struct {
	deadlineChan chan core.Duty
}

func (testDeadliner) Add(core.Duty) bool {
	return true
}

func (t testDeadliner) C() <-chan core.Duty {
	return t.deadlineChan
}

// testDutyData represents data for each duty.
type testDutyData struct {
	duty             core.Duty
	defSet           core.DutyDefinitionSet
	unsignedDataSet  core.UnsignedDataSet
	parSignedDataSet core.ParSignedDataSet
}

// setupData returns test duty data and pubkeys required to test tracker.
func setupData(t *testing.T, slots []int) ([]testDutyData, []core.PubKey) {
	t.Helper()

	const (
		vIdxA   = 1
		vIdxB   = 2
		notZero = 99 // Validation require non-zero values
	)

	pubkeysByIdx := map[eth2p0.ValidatorIndex]core.PubKey{
		vIdxA: testutil.RandomCorePubKey(t),
		vIdxB: testutil.RandomCorePubKey(t),
	}

	var data []testDutyData

	for _, slot := range slots {
		duty := core.NewAttesterDuty(int64(slot))

		dutyA := eth2v1.AttesterDuty{
			Slot:             eth2p0.Slot(slot),
			ValidatorIndex:   vIdxA,
			CommitteeIndex:   vIdxA,
			CommitteeLength:  notZero,
			CommitteesAtSlot: notZero,
		}

		dutyB := eth2v1.AttesterDuty{
			Slot:             eth2p0.Slot(slot),
			ValidatorIndex:   vIdxB,
			CommitteeIndex:   vIdxB,
			CommitteeLength:  notZero,
			CommitteesAtSlot: notZero,
		}

		defset := core.DutyDefinitionSet{
			pubkeysByIdx[vIdxA]: core.NewAttesterDefinition(&dutyA),
			pubkeysByIdx[vIdxB]: core.NewAttesterDefinition(&dutyB),
		}

		unsignedset := make(core.UnsignedDataSet)
		unsignedset[pubkeysByIdx[vIdxA]] = testutil.RandomCoreAttestationData(t)
		unsignedset[pubkeysByIdx[vIdxB]] = testutil.RandomCoreAttestationData(t)

		parsignedset := make(core.ParSignedDataSet)
		parsignedset[pubkeysByIdx[vIdxA]] = core.ParSignedData{ShareIdx: 1}
		parsignedset[pubkeysByIdx[vIdxB]] = core.ParSignedData{ShareIdx: 1}

		data = append(data, testDutyData{
			duty:             duty,
			defSet:           defset,
			unsignedDataSet:  unsignedset,
			parSignedDataSet: parsignedset,
		})
	}

	return data, []core.PubKey{pubkeysByIdx[vIdxA], pubkeysByIdx[vIdxB]}
}
