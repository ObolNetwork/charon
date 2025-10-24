// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigdb

import (
	"context"
	"sync"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
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
			output: []int{0, 1, 2}, // Should return exactly threshold (3) signatures
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
	db := NewMemDB(th, deadliner)

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

func newTestDeadliner() *testDeadliner {
	return &testDeadliner{
		ch: make(chan core.Duty),
	}
}

type testDeadliner struct {
	added []core.Duty
	ch    chan core.Duty
}

// TestConcurrentSubscribeAndStore tests that there are no race conditions
// when subscribers are being added while Store operations are happening.
// This verifies the fix for race conditions when reading subscriber slices.
func TestConcurrentSubscribeAndStore(t *testing.T) {
	const (
		threshold = 3
		n         = 4
	)

	deadliner := newTestDeadliner()
	db := NewMemDB(threshold, deadliner)

	ctx := context.Background()

	// Start goroutines that continuously add subscribers
	var wg sync.WaitGroup

	for range 5 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 10 {
				db.SubscribeInternal(func(_ context.Context, _ core.Duty, _ core.ParSignedDataSet) error {
					return nil
				})
				db.SubscribeThreshold(func(_ context.Context, _ core.Duty, _ map[core.PubKey][]core.ParSignedData) error {
					return nil
				})
			}
		}()
	}

	// Store signatures (not concurrently to avoid race in testDeadliner)
	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomDenebVersionedAttestation()

	for i := range n {
		parAtt, err := core.NewPartialVersionedAttestation(att, i+1)
		require.NoError(t, err)

		_ = db.StoreInternal(ctx, core.NewAttesterDuty(123), core.ParSignedDataSet{
			pubkey: parAtt,
		})
	}

	wg.Wait()
}

// TestNoMultipleThresholdNotifications tests that threshold subscribers are only
// notified once per key, even when more than threshold signatures are stored.
func TestNoMultipleThresholdNotifications(t *testing.T) {
	const (
		threshold = 3
		n         = 10
	)

	deadliner := newTestDeadliner()
	db := NewMemDB(threshold, deadliner)

	ctx := t.Context()

	go db.Trim(ctx)

	notificationCount := 0

	db.SubscribeThreshold(func(_ context.Context, _ core.Duty, _ map[core.PubKey][]core.ParSignedData) error {
		notificationCount++
		return nil
	})

	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomDenebVersionedAttestation()

	// Store all n signatures one by one
	for i := range n {
		parAtt, err := core.NewPartialVersionedAttestation(att, i+1)
		require.NoError(t, err)
		err = db.StoreExternal(context.Background(), core.NewAttesterDuty(123), core.ParSignedDataSet{
			pubkey: parAtt,
		})
		require.NoError(t, err)
	}

	// Should be notified exactly once, not once per signature after threshold
	require.Equal(t, 1, notificationCount, "Should only notify once when threshold reached, not multiple times")
}

// TestNewMemDBValidation tests that NewMemDB validates its inputs.
func TestNewMemDBValidation(t *testing.T) {
	t.Run("valid inputs succeed", func(t *testing.T) {
		db := NewMemDB(3, newTestDeadliner())
		require.NotNil(t, db)
	})
}

// TestDeterministicThresholdMatching verifies that getThresholdMatching returns
// consistent results across multiple calls with the same input.
func TestDeterministicThresholdMatching(t *testing.T) {
	const (
		threshold = 3
		n         = 5
	)

	// Create attestations with same data but different share indices
	att := testutil.RandomDenebVersionedAttestation()

	var sigs []core.ParSignedData
	for i := range n {
		parAtt, err := core.NewPartialVersionedAttestation(att, i+1)
		require.NoError(t, err)

		sigs = append(sigs, parAtt)
	}

	// Call getThresholdMatching multiple times
	var results [][]int // Track ShareIdx of returned signatures

	for range 10 {
		result, ok, err := getThresholdMatching(core.DutyAttester, sigs, threshold)
		require.NoError(t, err)
		require.True(t, ok)
		require.Len(t, result, threshold)

		var shareIndices []int
		for _, sig := range result {
			shareIndices = append(shareIndices, sig.ShareIdx)
		}

		results = append(results, shareIndices)
	}

	// All results should be identical (deterministic)
	expected := results[0]
	for i, result := range results {
		require.Equal(t, expected, result, "Result %d differs from first result", i)
	}

	// Should be sorted by ShareIdx
	require.Equal(t, []int{1, 2, 3}, expected, "Should return lowest ShareIdx values in order")
}

func (t *testDeadliner) Expire() bool {
	for _, d := range t.added {
		t.ch <- d
	}

	t.ch <- core.Duty{} // Dummy duty to ensure all piped duties above were processed.

	t.added = nil

	return true
}

func (t *testDeadliner) Add(duty core.Duty) bool {
	t.added = append(t.added, duty)
	return true
}

func (t *testDeadliner) C() <-chan core.Duty {
	return t.ch
}
