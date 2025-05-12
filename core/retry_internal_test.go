// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/retry"
)

func TestWithAsyncRetry(t *testing.T) {
	var retryer, submitRetryer *retry.Retryer[Duty]

	retryer = retry.New(func(_ Duty) (time.Time, bool) {
		// shall be in the future, allows for at least 2 retries
		return time.Now().Add(3 * time.Second), true
	})
	submitRetryer = retry.New(func(_ Duty) (time.Time, bool) {
		// shall allow for little time window, to not retry
		return time.Now().Add(10 * time.Millisecond), true
	})

	var (
		fetcherFetchCount         atomic.Int32
		consensusParticipateCount atomic.Int32
		consensusProposeCount     atomic.Int32
		parSigExBroadcastCount    atomic.Int32
		broadcasterBroadcastCount atomic.Int32
	)

	wireOption := WithAsyncRetry(retryer, submitRetryer)
	var wf wireFuncs
	wf.FetcherFetch = func(_ context.Context, _ Duty, _ DutyDefinitionSet) error {
		fetcherFetchCount.Add(1)
		return errors.New("retryable") // shall trigger a retry
	}
	wf.ConsensusParticipate = func(_ context.Context, _ Duty) error {
		consensusParticipateCount.Add(1)
		return errors.New("retryable") // shall trigger a retry
	}
	wf.ConsensusPropose = func(_ context.Context, _ Duty, _ UnsignedDataSet) error {
		consensusProposeCount.Add(1)
		return errors.New("retryable") // shall trigger a retry
	}
	wf.ParSigExBroadcast = func(_ context.Context, _ Duty, _ ParSignedDataSet) error {
		parSigExBroadcastCount.Add(1)
		return errors.New("retryable") // shall trigger a retry
	}
	wf.BroadcasterBroadcast = func(_ context.Context, _ Duty, _ SignedDataSet) error {
		broadcasterBroadcastCount.Add(1)
		return errors.New("retryable") // shall not trigger a retry due to late deadline
	}
	wireOption(&wf)

	// Check that the functions are wrapped correctly
	require.NotNil(t, wf.FetcherFetch)
	require.NotNil(t, wf.ConsensusParticipate)
	require.NotNil(t, wf.ConsensusPropose)
	require.NotNil(t, wf.ParSigExBroadcast)
	require.NotNil(t, wf.BroadcasterBroadcast)

	duty := NewProposerDuty(1)

	err := wf.BroadcasterBroadcast(t.Context(), duty, SignedDataSet{})
	require.NoError(t, err)

	err = wf.ParSigExBroadcast(t.Context(), duty, ParSignedDataSet{})
	require.NoError(t, err)

	err = wf.FetcherFetch(t.Context(), duty, DutyDefinitionSet{})
	require.NoError(t, err)

	err = wf.ConsensusParticipate(t.Context(), duty)
	require.NoError(t, err)

	err = wf.ConsensusPropose(t.Context(), duty, UnsignedDataSet{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		// all functions except BroadcasterBroadcast should have been called at least 3 times
		// BroadcasterBroadcast should have been called once (no retry attemptted)
		return broadcasterBroadcastCount.Load() == 1 &&
			parSigExBroadcastCount.Load() >= 3 &&
			fetcherFetchCount.Load() >= 3 &&
			consensusParticipateCount.Load() >= 3 &&
			consensusProposeCount.Load() >= 3
	}, 10*time.Second, 10*time.Millisecond)

	retryer.Shutdown(t.Context())
	submitRetryer.Shutdown(t.Context())
}
