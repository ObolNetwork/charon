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
			require.Equal(t, msg, "consensus algorithm didn't complete")
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, _ map[int]bool, _ map[int]bool) {}

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
			require.Equal(t, msg, "")
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

func TestAnalyseDutyFailed(t *testing.T) {
	slot := 1
	attDuty := core.NewAttesterDuty(int64(slot))
	proposerDuty := core.NewProposerDuty(int64(slot))
	randaoDuty := core.NewRandaoDuty(int64(slot))

	t.Run("Failed", func(t *testing.T) {
		// Failed at fetcher
		events := map[core.Duty][]event{
			attDuty: {
				{
					duty:      attDuty,
					component: scheduler,
				},
			},
		}

		failed, comp, msg := analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, fetcher)
		require.Equal(t, msg, "couldn't fetch duty data from the beacon node")

		// Failed at consensus
		events[attDuty] = append(events[attDuty], event{
			duty:      attDuty,
			component: fetcher,
		})

		failed, comp, msg = analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, consensus)
		require.Equal(t, msg, "consensus algorithm didn't complete")

		// Failed at validatorAPI
		events[attDuty] = append(events[attDuty], event{
			duty:      attDuty,
			component: consensus,
		})

		failed, comp, msg = analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, validatorAPI)
		require.Equal(t, msg, "signed duty not submitted by local validator client")

		// Failed at parsigDBInternal
		events[attDuty] = append(events[attDuty], event{
			duty:      attDuty,
			component: validatorAPI,
		})

		failed, comp, msg = analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, parSigDBInternal)
		require.Equal(t, msg, "partial signature database didn't trigger partial signature exchange")

		// Failed at parsigEx
		events[attDuty] = append(events[attDuty], event{
			duty:      attDuty,
			component: parSigDBInternal,
		})

		failed, comp, msg = analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, parSigEx)
		require.Equal(t, msg, "no partial signatures received from peers")

		// Failed at parsigDBThreshold
		events[attDuty] = append(events[attDuty], event{
			duty:      attDuty,
			component: parSigEx,
		})

		failed, comp, msg = analyseDutyFailed(attDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, parSigDBThreshold)
		require.Equal(t, msg, "insufficient partial signatures received, minimum required threshold not reached")
	})

	t.Run("FailedAtFetcherAsRandaoFailed", func(t *testing.T) {
		// Randao failed at parSigEx
		events := map[core.Duty][]event{
			proposerDuty: {
				{
					duty:      proposerDuty,
					component: scheduler,
				},
			},
			randaoDuty: {
				{
					duty:      proposerDuty,
					component: validatorAPI,
				},
				{
					duty:      proposerDuty,
					component: parSigDBInternal,
				},
			},
		}

		failed, comp, msg := analyseDutyFailed(proposerDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, fetcher)
		require.Equal(t, msg, "couldn't propose block since randao duty failed")

		// Randao failed at parSigDBThreshold
		events[randaoDuty] = append(events[randaoDuty], event{
			duty:      proposerDuty,
			component: parSigEx,
		})

		failed, comp, msg = analyseDutyFailed(proposerDuty, events)
		require.True(t, failed)
		require.Equal(t, comp, fetcher)
		require.Equal(t, msg, "couldn't propose block due to insufficient partial randao signatures")
	})

	t.Run("DutySuccess", func(t *testing.T) {
		events := map[core.Duty][]event{
			attDuty: {
				{
					duty:      attDuty,
					component: scheduler,
				},
				{
					duty:      attDuty,
					component: fetcher,
				},
				{
					duty:      attDuty,
					component: consensus,
				},
				{
					duty:      attDuty,
					component: validatorAPI,
				},
				{
					duty:      attDuty,
					component: parSigDBInternal,
				},
				{
					duty:      attDuty,
					component: parSigEx,
				},
				{
					duty:      attDuty,
					component: parSigDBThreshold,
				},
			},
		}

		failed, comp, msg := analyseDutyFailed(proposerDuty, events)
		require.False(t, failed)
		require.Equal(t, comp, sigAgg)
		require.Equal(t, msg, "")
	})
}

func TestDutyFailedComponent(t *testing.T) {
	var events []event
	for comp := scheduler; comp < sentinel; comp++ {
		events = append(events, event{component: comp})
	}

	t.Run("DutySuccess", func(t *testing.T) {
		failed, comp := dutyFailedComponent(events)
		require.False(t, failed)
		require.Equal(t, comp, sigAgg)
	})

	t.Run("EmptyEvents", func(t *testing.T) {
		f, comp := dutyFailedComponent([]event{})
		require.False(t, f)
		require.Equal(t, comp, sentinel)
	})

	t.Run("DutyFailed", func(t *testing.T) {
		// Remove the last component (sigAgg) from the events array.
		events = events[:len(events)-1]
		f, comp := dutyFailedComponent(events)
		require.True(t, f)
		require.Equal(t, comp, sigAgg)

		// Remove the second-last component (parsigDBThreshold) from the events array.
		events = events[:len(events)-1]
		f, comp = dutyFailedComponent(events)
		require.True(t, f)
		require.Equal(t, comp, parSigDBThreshold)
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

	var (
		count             int
		lastParticipation map[int]bool
	)
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[int]bool, _ map[int]bool) {
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
			require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defSet))
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

func TestUnexpectedParticipation(t *testing.T) {
	const (
		slot           = 123
		unexpectedPeer = 2
	)

	var peers []p2p.Peer
	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	data := core.NewPartialSignature(testutil.RandomCoreSignature(), unexpectedPeer)
	pubkey := testutil.RandomCorePubKey(t)
	participation := make(map[int]bool)

	duties := []core.Duty{
		core.NewRandaoDuty(slot),
		core.NewProposerDuty(slot),
		core.NewAttesterDuty(slot),
		core.NewBuilderProposerDuty(slot),
	}

	for _, d := range duties {
		t.Run(d.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			tr := New(deadliner, peers)

			tr.participationReporter = func(_ context.Context, duty core.Duty, participatedShares map[int]bool, unexpectedPeers map[int]bool) {
				require.Equal(t, d, duty)
				require.True(t, reflect.DeepEqual(unexpectedPeers, map[int]bool{unexpectedPeer: true}))
				require.True(t, reflect.DeepEqual(participatedShares, participation))
				cancel()
			}

			go func(duty core.Duty) {
				require.NoError(t, tr.ParSigExEvent(ctx, duty, core.ParSignedDataSet{pubkey: data}))
				deadliner.deadlineChan <- duty
			}(d)

			require.ErrorIs(t, tr.Run(ctx), context.Canceled)
		})
	}
}

func TestDutyRandaoExpected(t *testing.T) {
	const (
		slot      = 123
		validPeer = 1
	)

	dutyRandao := core.NewRandaoDuty(slot)
	dutyProposer := core.NewProposerDuty(slot)

	var peers []p2p.Peer
	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}

	data := core.NewPartialSignature(testutil.RandomCoreSignature(), validPeer)
	pubkey := testutil.RandomCorePubKey(t)
	participation := map[int]bool{validPeer: true}
	unexpected := make(map[int]bool)

	ctx, cancel := context.WithCancel(context.Background())
	tr := New(deadliner, peers)

	tr.participationReporter = func(_ context.Context, duty core.Duty, participatedShares map[int]bool, unexpectedPeers map[int]bool) {
		require.Equal(t, dutyRandao, duty)
		require.True(t, reflect.DeepEqual(unexpectedPeers, unexpected))
		require.True(t, reflect.DeepEqual(participatedShares, participation))

		cancel()
	}

	go func() {
		require.NoError(t, tr.SchedulerEvent(ctx, dutyProposer, core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(testutil.RandomProposerDuty(t))}))
		require.NoError(t, tr.ParSigExEvent(ctx, dutyRandao, core.ParSignedDataSet{pubkey: data}))

		deadliner.deadlineChan <- dutyRandao
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
