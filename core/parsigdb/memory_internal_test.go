// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestGetThresholdMatching(t *testing.T) {
	const n = 4

	tests := []struct {
		name   string
		input  []int
		output []int
	}{
		{
			name:   "empty",
			output: nil,
		},
		{
			name:   "all identical exact threshold",
			input:  []int{0, 0, 0},
			output: []int{0, 1, 2},
		},
		{
			name:   "all identical above threshold",
			input:  []int{0, 0, 0, 0},
			output: nil,
		},
		{
			name:   "one odd",
			input:  []int{0, 0, 1, 0},
			output: []int{0, 1, 3},
		},
		{
			name:   "two odd",
			input:  []int{0, 0, 1, 1},
			output: nil,
		},
	}

	slot := testutil.RandomSlot()
	valIdx := testutil.RandomVIdx()
	roots := []eth2p0.Root{
		testutil.RandomRoot(),
		testutil.RandomRoot(),
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test different msg type using providers.
			providers := map[string]func(int) core.ParSignedData{
				"SyncCommitteeMessage": func(i int) core.ParSignedData {
					msg := &altair.SyncCommitteeMessage{
						Slot:            slot,
						BeaconBlockRoot: roots[test.input[i]], // Vary root based on input.
						ValidatorIndex:  valIdx,
						Signature:       testutil.RandomEth2Signature(),
					}

					return core.NewPartialSignedSyncMessage(msg, i+1)
				},
				"Selection": func(i int) core.ParSignedData {
					// Message is constant
					msg := &eth2v1.BeaconCommitteeSelection{
						ValidatorIndex: valIdx,
						Slot:           eth2p0.Slot(test.input[i]), // Vary slot based on input
						SelectionProof: testutil.RandomEth2Signature(),
					}

					return core.NewPartialSignedBeaconCommitteeSelection(msg, i+1)
				},
			}

			for name, provider := range providers {
				t.Run(name, func(t *testing.T) {
					var datas []core.ParSignedData
					for i := range len(test.input) {
						datas = append(datas, provider(i))
					}

					th := cluster.Threshold(n)

					out, ok, err := getThresholdMatching(1, datas, th)
					require.NoError(t, err)
					require.Equal(t, len(out) == th, ok)

					var expect []core.ParSignedData
					for _, i := range test.output {
						expect = append(expect, datas[i])
					}

					require.Equal(t, expect, out)
				})
			}
		})
	}
}

func TestMemDBThreshold(t *testing.T) {
	const (
		th = 7
		n  = 10
	)

	deadliner := newTestDeadliner()
	db := NewMemDB(th, deadliner, NewMemDBMetadata(eth2util.Mainnet.SlotDuration, time.Unix(eth2util.Mainnet.GenesisTimestamp, 0)))

	ctx := t.Context()

	go db.Trim(ctx)

	timesCalled := 0

	db.SubscribeThreshold(func(_ context.Context, _ core.Duty, _ map[core.PubKey][]core.ParSignedData) error {
		timesCalled++

		return nil
	})

	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomDenebVersionedAttestation()

	enqueueN := func() {
		for i := range n {
			parAtt, err := core.NewPartialVersionedAttestation(att, i+1)
			require.NoError(t, err)
			err = db.StoreExternal(context.Background(), core.NewAttesterDuty(123), core.ParSignedDataSet{
				pubkey: parAtt,
			})
			require.NoError(t, err)
		}
	}

	enqueueN()
	require.Equal(t, 1, timesCalled)

	deadliner.Expire()

	enqueueN()
	require.Equal(t, 2, timesCalled)
}

// TestMemDBStoreExternalExpired verifies that StoreExternal drops partial signatures for duties the
// deadliner reports as already expired (which can never be trimmed and would otherwise leak), while
// still storing scheduled and never-expiring duties.
func TestMemDBStoreExternalExpired(t *testing.T) {
	tests := []struct {
		name             string
		status           core.DeadlineStatus
		wantStored       bool // stored in entries
		wantInKeysByDuty bool // also tracked for deadliner trimming (non-exempt only)
	}{
		{name: "expired_dropped", status: core.DeadlineExpired, wantStored: false, wantInKeysByDuty: false},
		{name: "scheduled_stored", status: core.DeadlineScheduled, wantStored: true, wantInKeysByDuty: true},
		// Exempt duties are stored but tracked via exemptEntries (capped), not keysByDuty.
		{name: "exempt_stored", status: core.DeadlineExempt, wantStored: true, wantInKeysByDuty: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := NewMemDB(7, fixedDeadliner{status: tt.status}, NewMemDBMetadata(eth2util.Mainnet.SlotDuration, time.Unix(eth2util.Mainnet.GenesisTimestamp, 0)))

			pubkey := testutil.RandomCorePubKey(t)
			parAtt, err := core.NewPartialVersionedAttestation(testutil.RandomDenebVersionedAttestation(), 1)
			require.NoError(t, err)

			err = db.StoreExternal(context.Background(), core.NewAttesterDuty(123), core.ParSignedDataSet{pubkey: parAtt})
			require.NoError(t, err)

			db.mu.Lock()
			gotEntries, gotKeys := len(db.entries), len(db.keysByDuty)
			db.mu.Unlock()

			if tt.wantStored {
				require.Equal(t, 1, gotEntries)
			} else {
				require.Zero(t, gotEntries)
			}

			if tt.wantInKeysByDuty {
				require.Equal(t, 1, gotKeys)
			} else {
				require.Zero(t, gotKeys)
			}
		})
	}
}

// TestMemDBExemptCap verifies that exempt-duty entries are capped per share index per validator
// (evicting oldest), bounding memory against a peer that replays many distinct epochs/slots.
func TestMemDBExemptCap(t *testing.T) {
	const shareIdx = 1

	// fixedDeadliner returns DeadlineExempt for every duty, so all stored entries are treated as
	// exempt regardless of type, exercising the per-share cap.
	db := NewMemDB(7, fixedDeadliner{status: core.DeadlineExempt}, NewMemDBMetadata(eth2util.Mainnet.SlotDuration, time.Unix(eth2util.Mainnet.GenesisTimestamp, 0)))

	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomDenebVersionedAttestation()

	// Store more distinct slots than the cap, all for the same validator and share index.
	const stored = maxExemptEntriesPerShare + 5
	for slot := range uint64(stored) {
		parAtt, err := core.NewPartialVersionedAttestation(att, shareIdx)
		require.NoError(t, err)

		err = db.StoreExternal(context.Background(), core.NewAttesterDuty(slot), core.ParSignedDataSet{pubkey: parAtt})
		require.NoError(t, err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	require.Len(t, db.entries, maxExemptEntriesPerShare, "entries must be capped at maxExemptEntriesPerShare")
	require.Len(t, db.exemptEntries[exemptEntryKey{ShareIdx: shareIdx, PubKey: pubkey, DutyType: core.DutyAttester}], maxExemptEntriesPerShare)
}

// fixedDeadliner is a Deadliner that returns a fixed DeadlineStatus and never deadlines anything.
type fixedDeadliner struct {
	status core.DeadlineStatus
}

func (d fixedDeadliner) Add(core.Duty) core.DeadlineStatus { return d.status }

func (fixedDeadliner) C() <-chan core.Duty { return nil }

func newTestDeadliner() *testDeadliner {
	return &testDeadliner{
		ch: make(chan core.Duty),
	}
}

type testDeadliner struct {
	added []core.Duty
	ch    chan core.Duty
}

func (t *testDeadliner) Expire() bool {
	for _, d := range t.added {
		t.ch <- d
	}

	t.ch <- core.Duty{} // Dummy duty to ensure all piped duties above were processed.

	t.added = nil

	return true
}

func (t *testDeadliner) Add(duty core.Duty) core.DeadlineStatus {
	t.added = append(t.added, duty)
	return core.DeadlineScheduled
}

func (t *testDeadliner) C() <-chan core.Duty {
	return t.ch
}
