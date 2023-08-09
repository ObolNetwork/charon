// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"math/rand"
	"net/http"
	"reflect"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
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
	testData, pubkeys := setupData(t, []int{slot}, 3)

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		analyser := testDeadliner{deadlineChan: make(chan core.Duty)}
		deleter := testDeadliner{deadlineChan: make(chan core.Duty)}
		consensusErr := errors.New("consensus error")

		count := 0
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, step step, reason reason, err error) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, consensus, step)
			require.Equal(t, reason, reasonConsensus)
			require.ErrorIs(t, err, consensusErr)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(analyser, deleter, []p2p.Peer{}, 0)
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, failed bool, _ map[int]int, _ map[int]int, _ int) {
			require.True(t, failed)
		}

		go func() {
			for _, td := range testData {
				tr.FetcherFetched(td.duty, td.defSet, nil)
				tr.ConsensusProposed(td.duty, td.unsignedDataSet, consensusErr)

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
		failedDutyReporter := func(_ context.Context, failedDuty core.Duty, isFailed bool, step step, reason reason, _ error) {
			require.Equal(t, testData[0].duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, zero, step)
			require.Empty(t, reason)
			count++

			if count == len(testData) {
				cancel()
			}
		}

		tr := New(analyser, deleter, []p2p.Peer{}, 0)
		tr.failedDutyReporter = failedDutyReporter
		tr.participationReporter = func(_ context.Context, _ core.Duty, failed bool, _ map[int]int, _ map[int]int, _ int) {
			require.False(t, failed)
		}

		go func() {
			for _, td := range testData {
				tr.FetcherFetched(td.duty, td.defSet, nil)
				tr.ConsensusProposed(td.duty, td.unsignedDataSet, nil)
				tr.DutyDBStored(td.duty, td.unsignedDataSet, nil)
				tr.ParSigDBStoredInternal(td.duty, td.parSignedDataSet, nil)
				tr.ParSigDBStoredExternal(td.duty, td.parSignedDataSet, nil)
				for _, pubkey := range pubkeys {
					tr.SigAggAggregated(td.duty, map[core.PubKey][]core.ParSignedData{pubkey: nil}, nil)
					tr.BroadcasterBroadcast(td.duty, core.SignedDataSet{pubkey: nil}, nil)
					if lastStep(td.duty.Type) == chainInclusion {
						tr.InclusionChecked(td.duty, pubkey, nil, nil)
					}
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

	// Note the order of the events inserted by subtests below is important.
	events := make(map[core.Duty][]event)

	t.Run("Failed at fetcher", func(t *testing.T) {
		fetcherErr := errors.New("fetcher failed")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    fetcher,
			stepErr: errors.New("fetcher failed"),
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorAs(t, err, &fetcherErr)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, reason, reasonFetcherError)
	})

	t.Run("Failed at consensus", func(t *testing.T) {
		consensusErr := errors.New("consensus failed")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    consensus,
			stepErr: errors.New("consensus failed"),
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorAs(t, err, &consensusErr)
		require.True(t, failed)
		require.Equal(t, step, consensus)
		require.Equal(t, reason, reasonConsensus)
	})

	// Failed at validatorAPI
	t.Run("Failed at validatorAPI", func(t *testing.T) {
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: dutyDB,
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.NoError(t, err)
		require.True(t, failed)
		require.Equal(t, step, validatorAPI)
		require.Equal(t, reason, reasonValidatorAPI)
	})
	// Failed at parsigDBInternal
	t.Run("Failed at parsigDBInternal", func(t *testing.T) {
		parSigDBInternalErr := errors.New("parsigdb_internal failed")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    parSigDBInternal,
			stepErr: errors.New("parsigdb_internal failed"),
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorAs(t, err, &parSigDBInternalErr)
		require.True(t, failed)
		require.Equal(t, step, parSigDBInternal)
		require.Equal(t, reason, reasonParSigDBInternal)
	})

	// Failed at parsigEx
	t.Run("Failed at parsigEx", func(t *testing.T) {
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: parSigEx,
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.NoError(t, err)
		require.True(t, failed)
		require.Equal(t, step, parSigEx)
		require.Equal(t, reason, reasonParSigExReceive)
	})

	// Failed at parsigDBInternal
	t.Run("Failed at parsigDBInternal", func(t *testing.T) {
		parSigDBExternalErr := errors.New("parsigdb_external failed")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    parSigDBExternal,
			stepErr: errors.New("parsigdb_external failed"),
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorAs(t, err, &parSigDBExternalErr)
		require.True(t, failed)
		require.Equal(t, step, parSigDBExternal)
		require.Equal(t, reason, reasonParSigDBExternal)
	})

	t.Run("Failed at parsigDBThreshold", func(t *testing.T) {
		events[attDuty] = append(events[attDuty], event{
			duty: attDuty,
			step: parSigDBExternal,
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.NoError(t, err)
		require.True(t, failed)
		require.Equal(t, step, parSigDBExternal)
		require.Equal(t, reason, reasonParSigDBInsufficient)

		failed, step, reason, err = analyseDutyFailed(attDuty, events, false)
		require.NoError(t, err)
		require.True(t, failed)
		require.Equal(t, step, parSigDBExternal)
		require.Equal(t, reason, reasonParSigDBInconsistent)

		events[syncMsgDuty] = events[attDuty]
		failed, step, reason, err = analyseDutyFailed(syncMsgDuty, events, false)
		require.NoError(t, err)
		require.True(t, failed)
		require.Equal(t, step, parSigDBExternal)
		require.Equal(t, reason, reasonParSigDBInconsistentSync)
	})

	t.Run("Failed at bcast", func(t *testing.T) {
		bcastErr := errors.New("bcast failed")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    bcast,
			stepErr: bcastErr,
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorIs(t, err, bcastErr)
		require.True(t, failed)
		require.Equal(t, step, bcast)
		require.Equal(t, reason, reasonBcast)
	})

	t.Run("Failed at chain inclusion", func(t *testing.T) {
		inclErr := errors.New("not included on chain")
		events[attDuty] = append(events[attDuty], event{
			duty:    attDuty,
			step:    chainInclusion,
			stepErr: inclErr,
		})

		failed, step, reason, err := analyseDutyFailed(attDuty, events, true)
		require.ErrorIs(t, err, inclErr)
		require.True(t, failed)
		require.Equal(t, step, chainInclusion)
		require.Equal(t, reason, reasonChainIncl)
	})

	t.Run("FailedAtFetcherAsRandaoFailed", func(t *testing.T) {
		// Randao failed at parSigExReceive/parSigDBExternal
		expectedErr := errors.New("failed to query randao")
		events := map[core.Duty][]event{
			proposerDuty: {
				{
					duty:    proposerDuty,
					step:    fetcher,
					stepErr: context.Canceled,
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
				{
					duty: proposerDuty,
					step: parSigEx,
				},
			},
		}

		failed, step, reason, err := analyseDutyFailed(proposerDuty, events, true)
		require.ErrorAs(t, err, &expectedErr)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, reason, reasonFetcherProposerNoExternalRandaos)

		// Randao failed at parSigDBThreshold
		events[randaoDuty] = append(events[randaoDuty], event{
			duty: proposerDuty,
			step: parSigDBExternal,
		})

		failed, step, reason, err = analyseDutyFailed(proposerDuty, events, true)
		require.ErrorAs(t, err, &expectedErr)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, reason, reasonFetcherProposerFewRandaos)

		// No Randaos
		events[randaoDuty] = nil

		failed, step, reason, err = analyseDutyFailed(proposerDuty, events, true)
		require.ErrorAs(t, err, &expectedErr)
		require.True(t, failed)
		require.Equal(t, step, fetcher)
		require.Equal(t, reason, reasonFetcherProposerZeroRandaos)
	})

	t.Run("Attester Duty Success", func(t *testing.T) {
		var (
			events  = make(map[core.Duty][]event)
			attDuty = core.NewAttesterDuty(int64(1))
		)

		require.Equal(t, chainInclusion, lastStep(attDuty.Type))

		for step := fetcher; step < sentinel; step++ {
			events[attDuty] = append(events[attDuty], event{step: step, duty: attDuty})
		}

		failed, step, msg, err := analyseDutyFailed(attDuty, events, true)
		require.NoError(t, err)
		require.False(t, failed)
		require.Equal(t, zero, step)
		require.Empty(t, msg)
	})

	t.Run("SyncContrib Duty Success", func(t *testing.T) {
		var (
			events          = make(map[core.Duty][]event)
			syncContribDuty = core.NewSyncContributionDuty(int64(1))
		)

		require.Equal(t, bcast, lastStep(syncContribDuty.Type))

		for step := fetcher; step < chainInclusion; step++ {
			events[attDuty] = append(events[attDuty], event{step: step, duty: syncContribDuty})
		}

		failed, step, msg, err := analyseDutyFailed(attDuty, events, true)
		require.NoError(t, err)
		require.False(t, failed)
		require.Equal(t, zero, step)
		require.Empty(t, msg)
	})
}

func TestDutyFailedStep(t *testing.T) {
	var events []event
	for step := fetcher; step < sentinel; step++ {
		events = append(events, event{step: step, duty: core.NewAttesterDuty(0)})
	}

	t.Run("DutySuccess", func(t *testing.T) {
		failed, step, err := dutyFailedStep(events)
		require.NoError(t, err)
		require.False(t, failed)
		require.Equal(t, zero, step)
	})

	t.Run("EmptyEvents", func(t *testing.T) {
		f, step, err := dutyFailedStep([]event{})
		require.NoError(t, err)
		require.True(t, f)
		require.Equal(t, zero, step)
	})
}

func TestTrackerParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	slots := []int{1, 2, 3}
	testData, pubkeys := setupData(t, slots, 3)

	// Assuming a DV with 4 nodes.
	numPeers := 4
	var peers []p2p.Peer
	for i := 0; i < numPeers; i++ {
		peers = append(peers, p2p.Peer{Index: i})
	}

	// Participation set per duty for a cluster.
	expectedParticipationPerDuty := map[core.Duty]map[int]int{
		testData[0].duty: {
			1: len(pubkeys),
			2: len(pubkeys),
			3: len(pubkeys),
			4: len(pubkeys),
		},
		testData[1].duty: {
			1: len(pubkeys),
			2: len(pubkeys),
			4: len(pubkeys),
		},
		testData[2].duty: {
			1: len(pubkeys),
			2: len(pubkeys),
			4: len(pubkeys),
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
				if expectedParticipationPerDuty[td.duty][p.ShareIdx()] == 0 {
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
		lastParticipation map[int]int
	)
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, failed bool, actualParticipation map[int]int, _ map[int]int, _ int) {
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
	tr.failedDutyReporter = func(context.Context, core.Duty, bool, step, reason, error) {}

	go func() {
		for _, td := range testData {
			tr.FetcherFetched(td.duty, td.defSet, nil)
			tr.ParSigDBStoredInternal(td.duty, td.parSignedDataSet, nil)
			for _, data := range psigDataPerDutyPerPeer[td.duty] {
				tr.ParSigDBStoredExternal(td.duty, data, nil)
			}
			for _, pk := range pubkeys {
				tr.SigAggAggregated(td.duty, map[core.PubKey][]core.ParSignedData{pk: nil}, nil)
				tr.BroadcasterBroadcast(td.duty, core.SignedDataSet{pk: nil}, nil)
				if lastStep(td.duty.Type) == chainInclusion {
					tr.InclusionChecked(td.duty, pk, nil, nil)
				}
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
	participation := make(map[int]int)

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

			tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]int, unexpectedPeers map[int]int, _ int) {
				require.Equal(t, d, duty)
				require.True(t, reflect.DeepEqual(unexpectedPeers, map[int]int{unexpectedPeer: 1}))
				require.True(t, reflect.DeepEqual(participatedShares, participation))
				require.True(t, failed)
				cancel()
			}

			go func(duty core.Duty) {
				tr.ParSigDBStoredExternal(duty, core.ParSignedDataSet{pubkey: data}, nil)
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
	participation := make(map[int]int)
	unexpected := map[int]int{1: 1}

	ctx, cancel := context.WithCancel(context.Background())
	tr := New(analyser, deleter, peers, 0)

	tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]int, unexpectedPeers map[int]int, totalParticipationExpected int) {
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
		tr.FetcherFetched(dutyProposer, core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(testutil.RandomProposerDuty(t))}, errors.New("failed to query randao"))
		tr.ParSigDBStoredExternal(dutyRandao, core.ParSignedDataSet{pubkey: data}, nil)

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
	participation := map[int]int{validPeer: 1}
	unexpected := make(map[int]int)

	ctx, cancel := context.WithCancel(context.Background())
	tr := New(analyser, deleter, peers, 0)

	tr.participationReporter = func(_ context.Context, duty core.Duty, failed bool, participatedShares map[int]int, unexpectedPeers map[int]int, totalParticipationExpected int) {
		if duty.Type == core.DutyProposer {
			return
		}

		require.Equal(t, 1, totalParticipationExpected)
		require.Equal(t, dutyRandao, duty)
		require.True(t, failed)
		require.True(t, reflect.DeepEqual(unexpectedPeers, unexpected))
		require.True(t, reflect.DeepEqual(participatedShares, participation))

		cancel()
	}

	go func() {
		tr.FetcherFetched(dutyProposer, core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(testutil.RandomProposerDuty(t))}, errors.New("failed to query randao"))
		tr.ParSigDBStoredExternal(dutyRandao, core.ParSignedDataSet{pubkey: data}, nil)

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
func setupData(t *testing.T, slots []int, numVals int) ([]testDutyData, []core.PubKey) {
	t.Helper()

	const notZero = 99 // Validation require non-zero values

	var pubkeys []core.PubKey
	pubkeysByIdx := make(map[eth2p0.ValidatorIndex]core.PubKey)
	for i := 0; i < numVals; i++ {
		pubkey := testutil.RandomCorePubKey(t)
		pubkeysByIdx[eth2p0.ValidatorIndex(i)] = pubkey
		pubkeys = append(pubkeys, pubkey)
	}

	var data []testDutyData
	for _, slot := range slots {
		duty := core.NewAttesterDuty(int64(slot))

		defset := make(core.DutyDefinitionSet)
		unsignedset := make(core.UnsignedDataSet)
		parsignedset := make(core.ParSignedDataSet)
		for i := 0; i < numVals; i++ {
			defset[pubkeysByIdx[eth2p0.ValidatorIndex(i)]] = core.NewAttesterDefinition(&eth2v1.AttesterDuty{
				Slot:             eth2p0.Slot(slot),
				ValidatorIndex:   eth2p0.ValidatorIndex(i),
				CommitteeIndex:   eth2p0.CommitteeIndex(i),
				CommitteeLength:  notZero,
				CommitteesAtSlot: notZero,
			})

			unsignedset[pubkeysByIdx[eth2p0.ValidatorIndex(i)]] = testutil.RandomCoreAttestationData(t)
			parsignedset[pubkeysByIdx[eth2p0.ValidatorIndex(i)]] = core.NewPartialAttestation(testutil.RandomAttestation(), 1)
		}

		data = append(data, testDutyData{
			duty:             duty,
			defSet:           defset,
			unsignedDataSet:  unsignedset,
			parSignedDataSet: parsignedset,
		})
	}

	return data, pubkeys
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

	tr.SigAggAggregated(core.NewAggregatorDuty(thisSlot), map[core.PubKey][]core.ParSignedData{"": nil}, nil)
	tr.ParSigDBStoredInternal(core.NewProposerDuty(thisSlot), nil, nil)
	tr.FetcherFetched(core.NewAggregatorDuty(thisSlot), nil, nil)

	require.Empty(t, tr.events)
	cancel()
	<-done
}

//nolint:maintidx
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
		reason reason
		failed bool
		err    error
	}{
		{
			name: "eth2 error",
			duty: dutyAtt,
			events: map[core.Duty][]event{
				dutyAtt: {event{
					duty: dutyAtt,
					step: fetcher,
					stepErr: errors.Wrap(eth2http.Error{
						Method:     http.MethodGet,
						Endpoint:   "/eth/v1/validator/attestation_data",
						StatusCode: 404,
						Data:       nil,
					}, "beacon api error"),
				}},
			},
			reason: reasonFetcherBN,
			failed: true,
			err: errors.Wrap(eth2http.Error{
				Method:     http.MethodGet,
				Endpoint:   "/eth/v1/validator/attestation_data",
				StatusCode: 404,
				Data:       nil,
			}, "beacon api error"),
		},
		{
			name: "beacon committee selections endpoint not inclSupported",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty:    dutyAgg,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
			},
			reason: reasonFetcherAggregatorZeroPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "no external DutyPrepareAggregator signatures received",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty:    dutyAgg,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: parSigEx,
				}},
			},
			reason: reasonFetcherAggregatorNoExternalPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "insufficient DutyPrepareAggregator signature",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty:    dutyAgg,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: parSigDBExternal,
				}},
			},
			reason: reasonFetcherAggregatorFewPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "DutyPrepareAggregator failed",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty:    dutyAgg,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: sigAgg,
				}},
			},
			reason: reasonFetcherAggregatorFailedPrepare,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "DutyAttester failed",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty:    dutyAgg,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: bcast,
				}},
				dutyAtt: {event{
					duty:    dutyAtt,
					step:    fetcher,
					stepErr: errors.New("some error"),
				}},
			},
			reason: reasonFetcherAggregatorNoAttData,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "no aggregator found",
			duty: dutyAgg,
			events: map[core.Duty][]event{
				dutyAgg: {event{
					duty: dutyAgg,
					step: fetcher,
				}},
				dutyPrepAgg: {event{
					duty: dutyPrepAgg,
					step: bcast,
				}},
				dutyAtt: {event{
					duty: dutyAtt,
					step: bcast,
				}},
			},
			failed: false,
			err:    nil,
		},
		{
			name: "sync committee selections endpoint not inclSupported",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty:    dutySyncCon,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
			},
			reason: reasonFetcherSyncContributionZeroPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "no external DutyPrepareSyncContribution signatures",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty:    dutySyncCon,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: parSigEx,
				}},
			},
			reason: reasonFetcherSyncContributionNoExternalPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "insufficient DutyPrepareSyncContribution signatures",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty:    dutySyncCon,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: parSigDBExternal,
				}},
			},
			reason: reasonFetcherSyncContributionFewPrepares,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "DutyPrepareSyncContribution failed",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty:    dutySyncCon,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: sigAgg,
				}},
			},
			reason: reasonFetcherSyncContributionFailedPrepare,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "DutySyncMessage failed",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty:    dutySyncCon,
					step:    fetcher,
					stepErr: context.Canceled,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: bcast,
				}},
				dutySyncMsg: {event{
					duty: dutySyncMsg,
					step: parSigEx,
				}},
			},
			reason: reasonFetcherSyncContributionNoSyncMsg,
			failed: true,
			err:    context.Canceled,
		},
		{
			name: "no sync committee aggregators found",
			duty: dutySyncCon,
			events: map[core.Duty][]event{
				dutySyncCon: {event{
					duty: dutySyncCon,
					step: fetcher,
				}},
				dutyPrepSyncCon: {event{
					duty: dutyPrepSyncCon,
					step: bcast,
				}},
				dutySyncMsg: {event{
					duty: dutySyncMsg,
					step: bcast,
				}},
			},
			failed: false,
			err:    nil,
		},
		{
			name: "unexpected error",
			duty: dutyAtt,
			events: map[core.Duty][]event{
				dutyAtt: {
					event{
						duty:    dutyAtt,
						step:    fetcher,
						stepErr: errors.New("unexpected error"),
					},
				},
			},
			reason: reasonFetcherError,
			failed: true,
			err:    errors.New("unexpected error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failed, step, reason, err := analyseDutyFailed(test.duty, test.events, true)
			if test.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorAs(t, err, &test.err)
			}
			require.Equal(t, test.failed, failed)
			require.Equal(t, reason, test.reason)
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
				core.NewProposerDuty(slot): {event{step: fetcher, pubkey: pubkey}},
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
				core.NewAttesterDuty(slot): {event{step: fetcher, pubkey: pubkey}},
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
				core.NewSyncContributionDuty(slot): {event{step: fetcher, pubkey: pubkey}},
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
			out:  false,
		},
		{
			name: "DutySyncMessage expected",
			duty: core.NewSyncMessageDuty(slot),
			events: map[core.Duty][]event{
				core.NewSyncContributionDuty(slot): {event{step: fetcher, pubkey: pubkey}},
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
	require.Empty(t, extractParSigs(context.Background(), nil))

	var events []event

	makeEvents := func(n int, pubkey string) {
		data := testutil.RandomBellatrixCoreVersionedSignedBeaconBlock()
		offset := len(events)
		for i := 0; i < n; i++ {
			data, err := data.SetSignature(testutil.RandomCoreSignature())
			require.NoError(t, err)
			events = append(events, event{
				pubkey: core.PubKey(pubkey),
				parSig: &core.ParSignedData{
					ShareIdx:   offset + i,
					SignedData: data,
				},
			})
		}
	}

	expect := map[int]string{
		4: "a",
		2: "a",
		6: "b",
	}
	for n, pubkey := range expect {
		makeEvents(n, pubkey)
	}

	allParSigMsgs := extractParSigs(context.Background(), events)

	lengths := make(map[int]string)
	for pubkey, parSigMsgs := range allParSigMsgs {
		for _, indexes := range parSigMsgs {
			lengths[len(indexes)] = string(pubkey)
		}
	}

	require.Equal(t, expect, lengths)
}

func TestDutyFailedMultipleEvents(t *testing.T) {
	duty := core.NewAttesterDuty(123)
	testErr := errors.New("test error")
	var events []event
	for step := fetcher; step < sentinel; step++ {
		for i := 0; i < 5; i++ {
			events = append(events, event{step: step, duty: duty, stepErr: testErr})
		}
	}

	// Failed at last step.
	failed, step, err := dutyFailedStep(events)
	require.True(t, failed)
	require.Equal(t, chainInclusion, step)
	require.ErrorIs(t, err, testErr)

	// No Failure.
	for step := fetcher; step < sentinel; step++ {
		events = append(events, event{step: step, duty: duty})
	}
	failed, step, err = dutyFailedStep(events)
	require.False(t, failed)
	require.Equal(t, zero, step)
	require.NoError(t, err)
}

func TestUnexpectedFailures(t *testing.T) {
	duty := core.NewAttesterDuty(123)
	tests := []struct {
		name    string
		stepErr error
		step    step
		events  map[core.Duty][]event
	}{
		{
			name:    "consensus failed with nil error",
			stepErr: nil,
			step:    consensus,
			events: map[core.Duty][]event{
				duty: {{duty: duty, step: consensus}},
			},
		},
		{
			name:    "parsigex broadcast failed with error",
			stepErr: errors.New("parsigex broadcast err"),
			step:    parSigEx,
			events: map[core.Duty][]event{
				duty: {{duty: duty, step: parSigEx, stepErr: errors.New("parsigex broadcast err")}},
			},
		},
		{
			name:    "consensus failed with nil error",
			stepErr: nil,
			step:    sigAgg,
			events: map[core.Duty][]event{
				duty: {{duty: duty, step: sigAgg}},
			},
		},
	}

	for _, test := range tests {
		failed, step, reason, err := analyseDutyFailed(duty, test.events, false)
		require.True(t, failed)
		require.Equal(t, step, test.step)
		require.Equal(t, reasonUnknown, reason)
		if test.stepErr == nil {
			require.NoError(t, err)
		} else {
			require.ErrorAs(t, err, &test.stepErr)
		}
	}
}

func TestIgnoreUnsupported(t *testing.T) {
	// Note these tests are stateful, so order is important.
	tests := []struct {
		name   string
		duty   core.Duty
		failed bool
		step   step
		reason reason
		result bool
	}{
		{
			name:   "Attester not ignored",
			duty:   core.NewAttesterDuty(123),
			failed: testutil.RandomBool(),
			step:   randomStep(),
			reason: reasonAggSigDB,
			result: false,
		},
		{
			name:   "Aggregator failed and ignored",
			duty:   core.NewAggregatorDuty(123),
			failed: true,
			step:   fetcher,
			reason: reasonFetcherAggregatorZeroPrepares,
			result: true,
		},
		{
			name:   "Aggregator success",
			duty:   core.NewAggregatorDuty(123),
			failed: false,
			step:   fetcher,
			reason: reasonFetcherAggregatorZeroPrepares,
			result: false,
		},
		{
			name:   "Aggregator failed but not ignored",
			duty:   core.NewAggregatorDuty(123),
			failed: true,
			step:   fetcher,
			reason: reasonFetcherAggregatorZeroPrepares,
			result: false,
		},
		{
			name:   "SyncContrib failed and ignored",
			duty:   core.NewSyncContributionDuty(123),
			failed: true,
			step:   fetcher,
			reason: reasonFetcherSyncContributionZeroPrepares,
			result: true,
		},
		{
			name:   "SyncContrib success",
			duty:   core.NewSyncContributionDuty(123),
			failed: false,
			step:   fetcher,
			reason: reasonFetcherSyncContributionZeroPrepares,
			result: false,
		},
		{
			name:   "SyncContrib failed but not ignored",
			duty:   core.NewSyncContributionDuty(123),
			failed: true,
			step:   fetcher,
			reason: reasonFetcherSyncContributionZeroPrepares,
			result: false,
		},
	}

	ignorer := newUnsupportedIgnorer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.result, ignorer(context.Background(), test.duty, test.failed, test.step, test.reason))
		})
	}
}

func randomStep() step {
	return step(rand.Intn(int(sentinel)))
}
