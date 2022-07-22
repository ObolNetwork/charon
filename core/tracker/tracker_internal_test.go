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
	"crypto/ecdsa"
	"math/rand"
	"reflect"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestTrackerFailedDuty(t *testing.T) {
	slots := []int{1}
	testData := setupData(t, slots)

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner{
			deadlineChan: make(chan core.Duty),
		}

		count := 0
		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, testData[count].duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, component, "consensus")

			count++
			if count == len(testData) {
				// Signal exit to central go routine.
				cancel()
			}
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			for _, td := range testData {
				require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defset))
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
		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, testData[count].duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, "sigAgg", component)
			count++

			if count == len(testData) {
				// Signal exit to central go routine.
				cancel()
			}
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			for _, td := range testData {
				require.NoError(t, tr.SchedulerEvent(ctx, td.duty, td.defset))
				require.NoError(t, tr.FetcherEvent(ctx, td.duty, td.unsignedDataSet))
				require.NoError(t, tr.ConsensusEvent(ctx, td.duty, td.unsignedDataSet))
				require.NoError(t, tr.ValidatorAPIEvent(ctx, td.duty, td.parSignedDataSet))
				require.NoError(t, tr.ParSigDBInternalEvent(ctx, td.duty, td.parSignedDataSet))
				require.NoError(t, tr.ParSigExEvent(ctx, td.duty, td.parSignedDataSet))

				for _, pk := range td.pubkeys {
					require.NoError(t, tr.ParSigDBThresholdEvent(ctx, td.duty, pk, nil))
					require.NoError(t, tr.SigAggEvent(ctx, td.duty, pk, nil))
				}

				// Explicitly mark the current duty as deadlined.
				deadliner.deadlineChan <- td.duty
			}
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})
}

func TestTrackerAllParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	slots := []int{1, 2, 3}
	testData := setupData(t, slots)

	numPeers := 3
	peers := testPeers(t, numPeers)
	expectedParticipation := make(map[core.PubKey]map[shareIdx]bool)
	for _, pk := range testData[0].pubkeys {
		expectedParticipation[pk] = make(map[shareIdx]bool)
		expectedParticipation[pk][1] = true // Own participation

		// Other peers participation.
		for _, peer := range peers {
			expectedParticipation[pk][shareIdx(peer.Index+1)] = true
		}
	}

	// ParSignedDataSet to be sent by ParSigExEvent corresponding to each peer.
	var pSigDataPerPeer []core.ParSignedDataSet
	for _, p := range peers {
		data := make(core.ParSignedDataSet)
		for _, pk := range testData[0].pubkeys {
			data[pk] = core.ParSignedData{ShareIdx: p.Index + 1}
		}
		pSigDataPerPeer = append(pSigDataPerPeer, data)
	}

	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(deadliner, peers)

	count := 0
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[core.PubKey]map[shareIdx]bool, _ map[core.PubKey]map[shareIdx]bool) {
		require.Equal(t, testData[count].duty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipation))
		count++

		if count == len(testData) {
			// Signal exit to central go routine.
			cancel()
		}
	}
	// Ignore failedDutyReporter part to isolate participation only
	tr.failedDutyReporter = func(core.Duty, bool, string, string) {}

	go func() {
		for _, td := range testData {
			require.NoError(t, tr.ParSigDBInternalEvent(ctx, td.duty, td.parSignedDataSet))
			for _, data := range pSigDataPerPeer {
				require.NoError(t, tr.ParSigExEvent(ctx, td.duty, data))
			}
			for _, pk := range td.pubkeys {
				require.NoError(t, tr.ParSigDBThresholdEvent(ctx, td.duty, pk, nil))
				require.NoError(t, tr.SigAggEvent(ctx, td.duty, pk, nil))
			}

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- td.duty
		}
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

func TestTrackerLessParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	slots := []int{1, 2, 3}
	testData := setupData(t, slots)

	numPeers := 3
	peers := testPeers(t, numPeers)
	expectedParticipation := make(map[core.PubKey]map[shareIdx]bool)
	for _, pk := range testData[0].pubkeys {
		expectedParticipation[pk] = make(map[shareIdx]bool)
		expectedParticipation[pk][1] = true // Own participation

		// Other peers participation
		for _, peer := range peers {
			expectedParticipation[pk][shareIdx(peer.Index+1)] = true
		}
		// Drop one peer
		delete(expectedParticipation[pk], shareIdx(peers[0].Index+1))
	}

	// ParSignedDataSet to be sent by ParSigExEvent corresponding to each peer.
	var pSigDataPerPeer []core.ParSignedDataSet
	for _, p := range peers {
		data := make(core.ParSignedDataSet)
		for _, pk := range testData[0].pubkeys {
			data[pk] = core.ParSignedData{ShareIdx: p.Index + 1}
		}
		pSigDataPerPeer = append(pSigDataPerPeer, data)
	}

	// Drop one peer
	pSigDataPerPeer = pSigDataPerPeer[1:]

	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(deadliner, peers)

	count := 0
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[core.PubKey]map[shareIdx]bool, _ map[core.PubKey]map[shareIdx]bool) {
		require.Equal(t, testData[count].duty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipation))
		count++

		if count == len(testData) {
			// Signal exit to central go routine.
			cancel()
		}
	}
	// Ignore failedDutyReporter part to isolate participation only
	tr.failedDutyReporter = func(core.Duty, bool, string, string) {}

	go func() {
		for _, td := range testData {
			require.NoError(t, tr.ParSigDBInternalEvent(ctx, td.duty, td.parSignedDataSet))
			for _, data := range pSigDataPerPeer {
				require.NoError(t, tr.ParSigExEvent(ctx, td.duty, data))
			}

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- td.duty
		}
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

func TestMultipleDuties(t *testing.T) {
}

func testPeers(t *testing.T, n int) []p2p.Peer {
	t.Helper()

	var resp []p2p.Peer
	for i := 1; i <= n; i++ {
		p2pKey, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(int64(i))))
		require.NoError(t, err)

		var r enr.Record
		r.SetSeq(0)

		err = enode.SignV4(&r, p2pKey)
		require.NoError(t, err)

		p, err := p2p.NewPeer(r, i)
		require.NoError(t, err)

		resp = append(resp, p)
	}

	return resp
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

// testData represents data for testing.
type testData struct {
	duty             core.Duty
	pubkeys          []core.PubKey
	defset           core.DutyDefinitionSet
	unsignedDataSet  core.UnsignedDataSet
	parSignedDataSet core.ParSignedDataSet
}

// setupData returns the data required to test tracker.
func setupData(t *testing.T, slots []int) []testData {
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

	var data []testData

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

		data = append(data, testData{
			duty:             duty,
			pubkeys:          []core.PubKey{pubkeysByIdx[vIdxA], pubkeysByIdx[vIdxB]},
			defset:           defset,
			unsignedDataSet:  unsignedset,
			parSignedDataSet: parsignedset,
		})
	}

	return data
}
