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
	duty, pubkeys, defSet, unsignedDataSet, parSignedDataSet := setupData(t)

	t.Run("FailAtConsensus", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deadliner := testDeadliner{
			deadlineChan: make(chan core.Duty),
		}

		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, duty, failedDuty)
			require.True(t, isFailed)
			require.Equal(t, component, "consensus")

			// Signal exit to central go routine.
			cancel()
		}

		tr := New(deadliner, []p2p.Peer{})
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
		deadliner := testDeadliner{
			deadlineChan: make(chan core.Duty),
		}

		failedDutyReporter := func(failedDuty core.Duty, isFailed bool, component string, msg string) {
			require.Equal(t, duty, failedDuty)
			require.False(t, isFailed)
			require.Equal(t, "sigAgg", component)

			// Signal exit to central go routine.
			cancel()
		}

		tr := New(deadliner, []p2p.Peer{})
		tr.failedDutyReporter = failedDutyReporter

		go func() {
			require.NoError(t, tr.SchedulerEvent(ctx, duty, defSet))
			require.NoError(t, tr.FetcherEvent(ctx, duty, unsignedDataSet))
			require.NoError(t, tr.ConsensusEvent(ctx, duty, unsignedDataSet))
			require.NoError(t, tr.ValidatorAPIEvent(ctx, duty, parSignedDataSet))
			require.NoError(t, tr.ParSigDBInternalEvent(ctx, duty, parSignedDataSet))
			require.NoError(t, tr.ParSigExEvent(ctx, duty, parSignedDataSet))
			for _, pk := range pubkeys {
				require.NoError(t, tr.ParSigDBThresholdEvent(ctx, duty, pk, nil))
				require.NoError(t, tr.SigAggEvent(ctx, duty, pk, nil))
			}

			// Explicitly mark the current duty as deadlined.
			deadliner.deadlineChan <- duty
		}()

		require.ErrorIs(t, tr.Run(ctx), context.Canceled)
	})
}

func TestTrackerAllParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	expectedDuty, pubkeys, _, _, internalPSignedDataSet := setupData(t)

	numPeers := 3
	peers := testPeers(t, numPeers)
	expectedParticipation := make(map[core.PubKey]map[shareIdx]bool)
	for _, pk := range pubkeys {
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
		for _, pk := range pubkeys {
			data[pk] = core.ParSignedData{ShareIdx: p.Index + 1}
		}
		pSigDataPerPeer = append(pSigDataPerPeer, data)
	}

	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(deadliner, peers)
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[core.PubKey]map[shareIdx]bool, _ map[core.PubKey]map[shareIdx]bool) {
		require.Equal(t, expectedDuty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipation))

		// Signal exit to central go routine.
		cancel()
	}
	// Ignore failedDutyReporter part to isolate participation only
	tr.failedDutyReporter = func(core.Duty, bool, string, string) {}

	go func() {
		require.NoError(t, tr.ParSigDBInternalEvent(ctx, expectedDuty, internalPSignedDataSet))
		for _, data := range pSigDataPerPeer {
			require.NoError(t, tr.ParSigExEvent(ctx, expectedDuty, data))
		}
		for _, pk := range pubkeys {
			require.NoError(t, tr.ParSigDBThresholdEvent(ctx, expectedDuty, pk, nil))
			require.NoError(t, tr.SigAggEvent(ctx, expectedDuty, pk, nil))
		}

		// Explicitly mark the current duty as deadlined.
		deadliner.deadlineChan <- expectedDuty
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
}

func TestTrackerLessParticipation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	expectedDuty, pubkeys, _, _, internalPSignedDataSet := setupData(t)

	numPeers := 3
	peers := testPeers(t, numPeers)
	expectedParticipation := make(map[core.PubKey]map[shareIdx]bool)
	for _, pk := range pubkeys {
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
		for _, pk := range pubkeys {
			data[pk] = core.ParSignedData{ShareIdx: p.Index + 1}
		}
		pSigDataPerPeer = append(pSigDataPerPeer, data)
	}

	// Drop one peer
	pSigDataPerPeer = pSigDataPerPeer[1:]

	deadliner := testDeadliner{deadlineChan: make(chan core.Duty)}
	tr := New(deadliner, peers)
	tr.participationReporter = func(_ context.Context, actualDuty core.Duty, actualParticipation map[core.PubKey]map[shareIdx]bool, _ map[core.PubKey]map[shareIdx]bool) {
		require.Equal(t, expectedDuty, actualDuty)
		require.True(t, reflect.DeepEqual(actualParticipation, expectedParticipation))

		// Signal exit to central go routine.
		cancel()
	}
	// Ignore failedDutyReporter part to isolate participation only
	tr.failedDutyReporter = func(core.Duty, bool, string, string) {}

	go func() {
		require.NoError(t, tr.ParSigDBInternalEvent(ctx, expectedDuty, internalPSignedDataSet))
		for _, data := range pSigDataPerPeer {
			require.NoError(t, tr.ParSigExEvent(ctx, expectedDuty, data))
		}

		// Explicitly mark the current duty as deadlined.
		deadliner.deadlineChan <- expectedDuty
	}()

	require.ErrorIs(t, tr.Run(ctx), context.Canceled)
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

// setupData returns the data required to test tracker.
func setupData(t *testing.T) (core.Duty, map[eth2p0.ValidatorIndex]core.PubKey, core.DutyDefinitionSet, core.UnsignedDataSet, core.ParSignedDataSet) {
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

	unsignedDataSet := make(core.UnsignedDataSet)
	for pubkey := range defSet {
		unsignedDataSet[pubkey] = testutil.RandomCoreAttestationData(t)
	}

	parSignedDataSet := make(core.ParSignedDataSet)
	for pubkey := range defSet {
		parSignedDataSet[pubkey] = core.ParSignedData{
			SignedData: nil,
			ShareIdx:   1,
		}
	}

	return duty, pubkeysByIdx, defSet, unsignedDataSet, parSignedDataSet
}
