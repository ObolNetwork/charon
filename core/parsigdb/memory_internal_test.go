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

	"github.com/obolnetwork/charon/app/errors"
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

// TestStoreErrorPaths tests error handling in the store function.
func TestStoreErrorPaths(t *testing.T) {
	ctx := context.Background()
	db := NewMemDB(3, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	// Create first signature
	sig1, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)

	// Store first signature successfully
	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig1})
	require.NoError(t, err)

	// Create a different attestation (mismatching data) with same ShareIdx
	att2 := testutil.RandomDenebVersionedAttestation()
	sig2, err := core.NewPartialVersionedAttestation(att2, 1) // Different data, same ShareIdx
	require.NoError(t, err)

	// Try to store the mismatching signature
	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig2})
	require.Error(t, err)
	require.ErrorContains(t, err, "mismatching partial signed data")
}

// TestStoreExternalWithSubscriberError tests error handling when subscriber callback fails.
func TestStoreExternalWithSubscriberError(t *testing.T) {
	ctx := context.Background()
	db := NewMemDB(2, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	// Subscribe with a callback that returns an error
	var callbackCount int

	callback := func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error {
		callbackCount++
		return errors.New("subscriber callback failed")
	}

	db.SubscribeThreshold(callback)

	// Store signatures - when threshold is reached, callback error should be returned
	sig1, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)
	sig2, err := core.NewPartialVersionedAttestation(att, 2)
	require.NoError(t, err)

	err = db.StoreExternal(ctx, duty, core.ParSignedDataSet{pubkey: sig1})
	require.NoError(t, err, "First signature should succeed")

	err = db.StoreExternal(ctx, duty, core.ParSignedDataSet{pubkey: sig2})
	require.Error(t, err, "Second signature should fail when callback fails")
	require.ErrorContains(t, err, "subscriber callback failed")
	require.Equal(t, 1, callbackCount)
}

// TestStoreInternalWithSubscriberError tests error handling in StoreInternal when subscriber fails.
func TestStoreInternalWithSubscriberError(t *testing.T) {
	ctx := context.Background()
	db := NewMemDB(3, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	// Subscribe with a callback that returns an error
	var callbackCalled bool

	callback := func(context.Context, core.Duty, core.ParSignedDataSet) error {
		callbackCalled = true
		return errors.New("internal subscriber failed")
	}

	db.SubscribeInternal(callback)

	// Store one signature - should fail due to internal subscriber error
	sig1, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)

	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig1})
	require.Error(t, err)
	require.ErrorContains(t, err, "internal subscriber failed")
	require.True(t, callbackCalled)
}

// TestStoreDuplicateSignature tests storing the same signature twice (idempotent).
func TestStoreDuplicateSignature(t *testing.T) {
	ctx := context.Background()
	db := NewMemDB(3, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	sig, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)

	// Store same signature twice - should be idempotent
	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig})
	require.NoError(t, err)

	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig})
	require.NoError(t, err, "Storing identical signature should succeed (idempotent)")
}

// TestGetThresholdMatchingWithMessageRootMismatch tests behavior when signatures have different MessageRoots.
func TestGetThresholdMatchingWithMessageRootMismatch(t *testing.T) {
	threshold := 3

	// Create attestations with different data (different MessageRoots)
	att1 := testutil.RandomDenebVersionedAttestation()
	att2 := testutil.RandomDenebVersionedAttestation() // Different attestation

	sig1, err := core.NewPartialVersionedAttestation(att1, 1)
	require.NoError(t, err)
	sig2, err := core.NewPartialVersionedAttestation(att2, 2) // Different MessageRoot
	require.NoError(t, err)
	sig3, err := core.NewPartialVersionedAttestation(att1, 3)
	require.NoError(t, err)

	sigs := []core.ParSignedData{sig1, sig2, sig3}

	// With mismatching roots and not enough of any single root, should return false, nil error
	result, ok, err := getThresholdMatching(core.DutyAttester, sigs, threshold)
	require.NoError(t, err)
	require.False(t, ok, "Should not reach threshold with mismatching roots")
	require.Nil(t, result)
}

// TestStoreExternalContextPropagation tests that context is properly propagated.
func TestStoreExternalContextPropagation(t *testing.T) {
	db := NewMemDB(2, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	sig, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)

	// Use valid context - StoreExternal should succeed
	ctx := context.Background()
	err = db.StoreExternal(ctx, duty, core.ParSignedDataSet{pubkey: sig})
	require.NoError(t, err)
}

// TestStoreInternalContextPropagation tests that context is properly propagated.
func TestStoreInternalContextPropagation(t *testing.T) {
	db := NewMemDB(2, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	sig, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)

	// Use valid context - StoreInternal should succeed
	ctx := context.Background()
	err = db.StoreInternal(ctx, duty, core.ParSignedDataSet{pubkey: sig})
	require.NoError(t, err)
}

// TestCloneWithErrorCoverage tests cloneWithError behavior.
func TestCloneWithErrorCoverage(t *testing.T) {
	// Test successful cloning
	pubkey := testutil.RandomCorePubKey(t)
	att := testutil.RandomDenebVersionedAttestation()

	sig1, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)
	sig2, err := core.NewPartialVersionedAttestation(att, 2)
	require.NoError(t, err)

	input := map[core.PubKey][]core.ParSignedData{
		pubkey: {sig1, sig2},
	}

	output, err := cloneWithError(input)
	require.NoError(t, err)
	require.Len(t, output, 1)
	require.Len(t, output[pubkey], 2)

	// Verify it's a deep copy
	require.NotSame(t, &input[pubkey][0], &output[pubkey][0])
}

// TestStoreExternalCloneError tests error handling when Clone fails in StoreExternal.
func TestStoreExternalCloneError(t *testing.T) {
	ctx := context.Background()
	db := NewMemDB(2, newTestDeadliner())

	pubkey := testutil.RandomCorePubKey(t)
	duty := core.NewAttesterDuty(99)
	att := testutil.RandomDenebVersionedAttestation()

	// Subscribe with callback
	var callbackCalled bool

	db.SubscribeThreshold(func(context.Context, core.Duty, map[core.PubKey][]core.ParSignedData) error {
		callbackCalled = true
		return nil
	})

	// Store signatures to reach threshold
	sig1, err := core.NewPartialVersionedAttestation(att, 1)
	require.NoError(t, err)
	sig2, err := core.NewPartialVersionedAttestation(att, 2)
	require.NoError(t, err)

	err = db.StoreExternal(ctx, duty, core.ParSignedDataSet{pubkey: sig1})
	require.NoError(t, err)

	// Second signature reaches threshold - callback should be called
	err = db.StoreExternal(ctx, duty, core.ParSignedDataSet{pubkey: sig2})
	require.NoError(t, err)
	require.True(t, callbackCalled)
}
