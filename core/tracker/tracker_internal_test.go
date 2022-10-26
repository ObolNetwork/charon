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

func TestStepString(t *testing.T) {
	for step := zero; step < sentinel; step++ {
		require.NotEmpty(t, step.String())
	}
}

func TestTrackerFailedDuty(t *testing.T) {
	const slot = 1
	testData, pubkeys := setupData(t, []int{slot})

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
		deleter := testDeadliner{deadlineChan: make(chan core.Duty)}

		count := 0
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, step step, msg string) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, consensus, step)
			require.Equal(t, msg, msgConsensus)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(analyser, deleter, []p2p.Peer{}, 0)
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, failed bool, _ map[int]bool, _ map[int]bool) {
			require.True(t, failed)
		}

		go func() {
			for _, td := range testData {
				require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defSet))
				require.NoError(t, tr.FetcherEvent(ctx, td.duty, td.unsignedDataSet))

				// Explicitly mark the current duty as deadlined.
				analyser.deadlineChan <- td.duty

				// Delete duty from events.
				deleter.deadlineChan <- td.duty
			}
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})

	t.Run("Success", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
		deleter := testDeadliner{deadlineChan: make(chan core.Duty)}

		count := 0
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, step step, msg string) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, zero, step)
			require.Empty(t, msg)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(analyser, deleter, []p2p.Peer{}, 0)
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, failed bool, _ map[int]bool, _ map[int]bool) {
			require.False(t, failed)
		}

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
				analyser.deadlineChan <- td.duty

				// Delete duty from events.
				deleter.deadlineChan <- td.duty
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
	syncMsgDuty := core.NewSyncMessageDuty(int64(slot))

	t.Run("Failed", func(t *testing.T) {
		// Failed at fetcher
		events := map[core.Duty][]event{
			attDuty: {
				{
					duty: attDuty,
					step: scheduler,
				},
			},
		}

		failed, step, msg := analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, msg, msgFetcher)

		// Failed at consensus
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: fetcher,
		})

		failed, step, msg = analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, consensus)
		require.Equal(t, msg, msgConsensus)

		// Failed at validatorAPI
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: consensus,
		})

		failed, step, msg = analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, validatorAPI)
		require.Equal(t, msg, msgValidatorAPI)

		// Failed at parsigDBInternal
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: validatorAPI,
		})

		failed, step, msg = analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, parSigDBInternal)
		require.Equal(t, msg, msgParSigDBInternal)

		// Failed at parsigEx
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: parSigDBInternal,
		})

		failed, step, msg = analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, parSigEx)
		require.Equal(t, msg, msgParSigEx)

		// Failed at parsigDBThreshold
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: parSigEx,
		})

		failed, step, msg = analyseDutyFailed(attDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, parSigDBThreshold)
		require.Equal(t, msg, msgParSigDBInsufficient)

		inconsistentParsigs := parsigsByMsg{
			testutil.RandomRoot(): nil,
			testutil.RandomRoot(): nil,
		}

		failed, step, msg = analyseDutyFailed(attDuty, events, inconsistentParsigs)
		require.True(t, failed)
		require.Equal(t, step, parSigDBThreshold)
		require.Equal(t, msg, msgParSigDBInconsistent)

		events[syncMsgDuty] = events[attDuty]
		failed, step, msg = analyseDutyFailed(syncMsgDuty, events, inconsistentParsigs)
		require.True(t, failed)
		require.Equal(t, step, parSigDBThreshold)
		require.Equal(t, msg, msgParSigDBInconsistentSync)
	})

	t.Run("FailedAtFetcherAsRandaoFailed", func(t *testing.T) {
		// Randao failed at parSigEx
		events := map[core.Duty][]event{
			proposerDuty: {
				{
					duty: proposerDuty,
					step: scheduler,
				},
			},
			randaoDuty: {
				{
					duty: proposerDuty,
					step: validatorAPI,
				},
				{
					duty: proposerDuty,
					step: parSigDBInternal,
				},
			},
		}

		failed, step, msg := analyseDutyFailed(proposerDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, msg, msgFetcherProposerFailedRandao)

		// Randao failed at parSigDBThreshold
		events[randaoDuty] = append(events[randaoDuty], event{
			duty: proposerDuty,
			step: parSigEx,
		})

		failed, step, msg = analyseDutyFailed(proposerDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, msg, msgFetcherProposerFewRandaos)

		// No Randaos
		events[randaoDuty] = nil

		failed, step, msg = analyseDutyFailed(proposerDuty, events, nil)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, msg, msgFetcherProposerZeroRandaos)
	})

	t.Run("DutySuccess", func(t *testing.T) {
		var (
			events  = make(map[core.Duty][]event)
			attDuty = core.NewAttesterDuty(int64(1))
		)

		for step := scheduler; step < sentinel; step++ {
			events[attDuty] = append(events[attDuty], event{step: step})
		}

		failed, step, msg := analyseDutyFailed(attDuty, events, nil)
		require.False(t, failed)
		require.Equal(t, zero, step)
		require.Empty(t, msg)
	})
}

func TestDutyFailedStep(t *testing.T) {
	var events []event
	for step := scheduler; step < sentinel; step++ {
		events = append(events, event{step: step})
	}

	t.Run("DutySuccess", func(t *testing.T) {
		failed, step := dutyFailedStep(events)
		require.False(t, failed)
		require.Equal(t, zero, step)
	})

	t.Run("EmptyEvents", func(t *testing.T) {
		f, step := dutyFailedStep([]event{})
		require.True(t, f)
		require.Equal(t, zero, step)
	})

	t.Run("DutyFailed", func(t *testing.T) {
		// Remove the last step (sigAgg) from the events array.
		events = events[:len(events)-1]
		f, step := dutyFailedStep(events)
		require.True(t, f)
		require.Equal(t, step, sigAgg)

		// Remove the second-last step (parsigDBThreshold) from the events array.
		events = events[:len(events)-1]
		f, step = dutyFailedStep(events)
		require.True(t, f)
		require.Equal(t, step, parSigDBThreshold)
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

				set[pk] = core.NewPartialAttestation(testutil.RandomAttestation(), p.ShareIdx())
			}

			data = append(data, set)
		}

		psigDataPerDutyPerPeer[td.duty] = data
	}

	analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
	deleter := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(analyser, deleter, peers, 0)

	var (
		count             int
		lastParticipation map[int]bool
	)
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, failed bool, actualParticipation map[int]bool, _ map[int]bool) {
		require.Equal(t, testData[count].duty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipationPerDuty[testData[count].duty]))
		require.False(t, failed)

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
	tr.failedDutyReporter = func(context.Context, core.Duty, bool, step, string) {}

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
			analyser.deadlineChan <- td.duty

			// Delete duty from events.
			deleter.deadlineChan <- td.duty
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
	analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
	deleter := testDeadliner{deadlineChan: make(chan core.Duty)}
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
			tr := New(analyser, deleter, peers, 0)

			tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedPeers map[int]bool) {
				require.Equal(t, d, duty)
				require.True(t, reflect.DeepEqual(unexpectedPeers, map[int]bool{unexpectedPeer: true}))
				require.True(t, reflect.DeepEqual(participatedShares, participation))
				require.True(t, failed)
				cancel()
			}

			go func(duty core.Duty) {
				require.NoError(t, tr.ParSigExEvent(ctx, duty, core.ParSignedDataSet{pubkey: data}))
				analyser.deadlineChan <- duty
				deleter.deadlineChan <- duty
			}(d)

			require.ErrorIs(t, tr.Run(ctx), context.Canceled)
		})
	}
}

func TestDutyRandaoUnexpected(t *testing.T) {
	const (
		slot      = 123
		validPeer = 1
	)

	dutyRandao := core.NewRandaoDuty(slot)
	dutyProposer := core.NewProposerDuty(slot)

	var peers []p2p.Peer
	analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
	deleter := testDeadliner{deadlineChan: make(chan core.Duty)}

	data := core.NewPartialSignature(testutil.RandomCoreSignature(), validPeer)
	pubkey := testutil.RandomCorePubKey(t)
	participation := make(map[int]bool)
	unexpected := map[int]bool{1: true}

	ctx, cancel := context.WithCancel(context.Background())
	tr := New(analyser, deleter, peers, 0)

	tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedPeers map[int]bool) {
		if duty.Type == core.DutyProposer {
			return
		}

		require.Equal(t, dutyRandao, duty)
		require.True(t, reflect.DeepEqual(unexpectedPeers, unexpected))
		require.True(t, reflect.DeepEqual(participatedShares, participation))
		require.True(t, failed)

		cancel()
	}

	go func() {
		require.NoError(t, tr.SchedulerEvent(ctx, dutyProposer, core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(testutil.RandomProposerDuty(t))}))
		require.NoError(t, tr.ParSigExEvent(ctx, dutyRandao, core.ParSignedDataSet{pubkey: data}))

		analyser.deadlineChan <- dutyProposer
		// Trim Proposer events before Randao deadline
		deleter.deadlineChan <- dutyProposer
		analyser.deadlineChan <- dutyRandao
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

func TestDutyRandaoExpected(t *testing.T) {
	const (
		slot      = 123
		validPeer = 1
	)

	dutyRandao := core.NewRandaoDuty(slot)
	dutyProposer := core.NewProposerDuty(slot)

	var peers []p2p.Peer
	analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
	deleter := testDeadliner{deadlineChan: make(chan core.Duty)}

	data := core.NewPartialSignature(testutil.RandomCoreSignature(), validPeer)
	pubkey := testutil.RandomCorePubKey(t)
	participation := map[int]bool{validPeer: true}
	unexpected := make(map[int]bool)

	ctx, cancel := context.WithCancel(context.Background())
	tr := New(analyser, deleter, peers, 0)

	tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]bool, unexpectedPeers map[int]bool) {
		if duty.Type == core.DutyProposer {
			return
		}

		require.Equal(t, dutyRandao, duty)
		require.True(t, failed)
		require.True(t, reflect.DeepEqual(unexpectedPeers, unexpected))
		require.True(t, reflect.DeepEqual(participatedShares, participation))

		cancel()
	}

	go func() {
		require.NoError(t, tr.SchedulerEvent(ctx, dutyProposer, core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(testutil.RandomProposerDuty(t))}))
		require.NoError(t, tr.ParSigExEvent(ctx, dutyRandao, core.ParSignedDataSet{pubkey: data}))

		analyser.deadlineChan <- dutyProposer
		analyser.deadlineChan <- dutyRandao
		// Trim Proposer events after Randao deadline
		deleter.deadlineChan <- dutyProposer
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

// testDeadliner is a mock analyser implementation.
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
		parsignedset[pubkeysByIdx[vIdxA]] = core.NewPartialAttestation(testutil.RandomAttestation(), 1)
		parsignedset[pubkeysByIdx[vIdxB]] = core.NewPartialAttestation(testutil.RandomAttestation(), 1)

		data = append(data, testDutyData{
			duty:             duty,
			defSet:           defset,
			unsignedDataSet:  unsignedset,
			parSignedDataSet: parsignedset,
		})
	}

	return data, []core.PubKey{pubkeysByIdx[vIdxA], pubkeysByIdx[vIdxB]}
}

func TestFromSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
	deleter := testDeadliner{deadlineChan: make(chan core.Duty)}

	const thisSlot = 1
	const fromSlot = 2
	tr := New(analyser, deleter, nil, fromSlot)

	go func() {
		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
		close(done)
	}()

	require.NoError(t, tr.SigAggEvent(ctx, core.NewAggregatorDuty(thisSlot), "", nil))
	require.NoError(t, tr.ValidatorAPIEvent(ctx, core.NewProposerDuty(thisSlot), nil))
	require.NoError(t, tr.SchedulerEvent(ctx, core.NewAggregatorDuty(thisSlot), nil))
	require.Empty(t, tr.events)
	cancel()
	<-done
}

func TestAnalyseFetcherFailed(t *testing.T) {
	const slot = 123
	dutyAgg := core.NewAggregatorDuty(slot)
	dutyPrepAgg := core.NewPrepareAggregatorDuty(slot)
	dutyAtt := core.NewAttesterDuty(slot)
	dutySyncCon := core.NewSyncContributionDuty(slot)
	dutySyncMsg := core.NewSyncMessageDuty(slot)
	dutyPrepSyncCon := core.NewPrepareSyncContributionDuty(slot)

	tests := []struct {
		name   string
		duty   core.Duty
		events map[core.Duty][]event
		msg    string
		failed bool
	}{
		{
			name: "beacon committee selections endpoint not supported",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: scheduler,
				}},
			},
			msg:    msgFetcherAggregatorZeroPrepares,
			failed: true,
		},
		{
			name: "insufficient DutyPrepareAggregator signature",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: scheduler,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: parSigEx,
				}},
			},
			msg:    msgFetcherAggregatorFewPrepares,
			failed: true,
		},
		{
			name: "DutyPrepareAggregator failed",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: scheduler,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: parSigDBThreshold,
				}},
			},
			msg:    msgFetcherAggregatorFailedPrepare,
			failed: true,
		},
		{
			name: "DutyAttester failed",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: scheduler,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: sigAgg,
				}},
				dutyAtt: {event{
					duty: dutyAtt,
					step: fetcher,
				}},
			},
			msg:    msgFetcherAggregatorNoAttData,
			failed: true,
		},
		{
			name: "no aggregator found",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: scheduler,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: sigAgg,
				}},
				dutyAtt: {event{
					duty: dutyAtt,
					step: sigAgg,
				}},
			},
			msg:    "",
			failed: false,
		},
		{
			name: "sync committee selections endpoint not supported",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: scheduler,
				}},
			},
			msg:    msgFetcherSyncContributionZeroPrepares,
			failed: true,
		},
		{
			name: "insufficient DutyPrepareSyncContribution signatures",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: scheduler,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: parSigEx,
				}},
			},
			msg:    msgFetcherSyncContributionFewPrepares,
			failed: true,
		},
		{
			name: "DutyPrepareSyncContribution failed",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: scheduler,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: parSigDBThreshold,
				}},
			},
			msg:    msgFetcherSyncContributionFailedPrepare,
			failed: true,
		},
		{
			name: "DutySyncMessage failed",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: scheduler,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: sigAgg,
				}},
				dutySyncMsg: {event{
					duty: dutySyncMsg,
					step: fetcher,
				}},
			},
			msg:    msgFetcherSyncContributionNoSyncMsg,
			failed: true,
		},
		{
			name: "no sync committee aggregators found",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: scheduler,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: sigAgg,
				}},
				dutySyncMsg: {event{
					duty: dutySyncMsg,
					step: sigAgg,
				}},
			},
			msg:    "",
			failed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failed, step, msg := analyseDutyFailed(test.duty, test.events, nil)
			require.Equal(t, failed, test.failed)
			require.Equal(t, test.msg, msg)
			require.Equal(t, fetcher, step)
		})
	}
}

func TestIsParSigEventExpected(t *testing.T) {
	const slot = 123
	pubkey := testutil.RandomCorePubKey(t)
	tests := []struct {
		name   string
		duty   core.Duty
		events map[core.Duty][]event
		out    bool
	}{
		{
			name: "DutyExit",
			duty: core.NewVoluntaryExit(slot),
			out:  true,
		},
		{
			name: "DutyBuilderRegistration",
			duty: core.NewBuilderRegistrationDuty(slot),
			out:  true,
		},
		{
			name: "DutyRandao expected",
			duty: core.NewRandaoDuty(slot),
			events: map[core.Duty][]event{
				core.NewProposerDuty(slot): {event{step: scheduler, pubkey: pubkey}},
			},
			out: true,
		},
		{
			name: "DutyRandao unexpected",
			duty: core.NewRandaoDuty(slot),
			out:  false,
		},
		{
			name: "DutyPrepareAggregator expected",
			duty: core.NewPrepareAggregatorDuty(slot),
			events: map[core.Duty][]event{
				core.NewAttesterDuty(slot): {event{step: scheduler, pubkey: pubkey}},
			},
			out: true,
		},
		{
			name: "DutyPrepareAggregator unexpected",
			duty: core.NewPrepareAggregatorDuty(slot),
			out:  false,
		},
		{
			name: "DutyPrepareSyncContribution expected",
			duty: core.NewPrepareSyncContributionDuty(slot),
			events: map[core.Duty][]event{
				core.NewSyncContributionDuty(slot): {event{step: scheduler, pubkey: pubkey}},
			},
			out: true,
		},
		{
			name: "DutyPrepareSyncContribution unexpected",
			duty: core.NewPrepareSyncContributionDuty(slot),
			out:  false,
		},
		{
			name: "DutySyncMessage unexpected",
			duty: core.NewSyncMessageDuty(slot),
			out:  true,
		},
		{
			name: "DutySyncMessage expected",
			duty: core.NewSyncMessageDuty(slot),
			events: map[core.Duty][]event{
				core.NewSyncContributionDuty(slot): {event{step: scheduler, pubkey: pubkey}},
			},
			out: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.out, isParSigEventExpected(test.duty, pubkey, test.events))
		})
	}
}

func TestAnalyseParSigs(t *testing.T) {
	require.Empty(t, analyseParSigs(nil))

	var events []event

	makeEvents := func(n int) {
		data := testutil.RandomCoreVersionSignedBeaconBlock(t)
		offset := len(events)
		for i := 0; i < n; i++ {
			data, err := data.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)
			events = append(events, event{
				parSig: &core.ParSignedData{
					ShareIdx:   offset + i,
					SignedData: data,
				},
			})
		}
	}

	expect := map[int]bool{
		4: true,
		2: true,
	}
	for n := range expect {
		makeEvents(n)
	}

	parSigMsgs := analyseParSigs(events)
	require.Len(t, parSigMsgs, len(expect))

	lengths := make(map[int]bool)
	for _, indexes := range parSigMsgs {
		lengths[len(indexes)] = true
	}
	require.Equal(t, expect, lengths)
}
